import base64
import requests
import psycopg2
from config import CLIENT_ID, CLIENT_SECRET, DATABASE_URL
from telegram import send_message_via_telegram

def get_twitter_username_and_profile(access_token):
    url = "https://api.twitter.com/2/users/me"
    headers = {"Authorization": f"Bearer {access_token}"}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json().get("data", {})
        username = data.get("username")
        profile_url = f"https://twitter.com/{username}" if username else None
        return username, profile_url
    else:
        print(f"Failed to fetch username. Status code: {response.status_code}")
        return None, None

def post_tweet(access_token, tweet_text):
    TWITTER_API_URL = "https://api.twitter.com/2/tweets"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {"text": tweet_text}
    
    response = requests.post(TWITTER_API_URL, json=payload, headers=headers)
    
    if response.status_code == 201:
        tweet_data = response.json()
        return f"Tweet posted successfully: {tweet_data['data']['id']}"
    else:
        error_message = response.json().get("detail", "Failed to post tweet")
        return f"Error posting tweet: {error_message}"

def refresh_token_in_db(refresh_token, username):
    if not refresh_token:
        send_message_via_telegram(f"❌ Cannot refresh token for @{username}: No refresh token provided")
        return None, None
        
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
    
    try:
        # Print debug info
        print(f"Refreshing token for @{username}")
        print(f"Using refresh token: {refresh_token[:20]}...")
        
        response = requests.post(token_url, headers=headers, data=data, timeout=10)
        print(f"Response status code: {response.status_code}")
        token_response = response.json()
        print(f"Response data: {token_response}")

        if response.status_code == 200:
            new_access_token = token_response.get('access_token')
            new_refresh_token = token_response.get('refresh_token')
            
            if not new_access_token or not new_refresh_token:
                send_message_via_telegram(f"❌ Invalid response from Twitter API for @{username}: Missing tokens")
                return None, None
            
            # Update tokens in database first
            try:
                conn = psycopg2.connect(DATABASE_URL, sslmode='require')
                cursor = conn.cursor()
                cursor.execute('UPDATE tokens SET access_token = %s, refresh_token = %s WHERE username = %s', 
                          (new_access_token, new_refresh_token, username))
                conn.commit()
                conn.close()
                
                # Now verify the new access token
                test_username, _ = get_twitter_username_and_profile(new_access_token)
                if not test_username:
                    send_message_via_telegram(f"❌ New access token validation failed for @{username}")
                    return None, None
                
                send_message_via_telegram(f"✅ Successfully refreshed and validated token for @{username}")
                return new_access_token, new_refresh_token
            except Exception as db_error:
                send_message_via_telegram(f"❌ Database error while updating token for @{username}: {str(db_error)}")
                return None, None
        else:
            error_msg = token_response.get('error_description', 'Unknown error')
            error_code = token_response.get('error', 'No error code')
            send_message_via_telegram(f"❌ Failed to refresh token for @{username}: {error_msg} (Code: {error_code})")
            return None, None
    except requests.exceptions.RequestException as e:
        send_message_via_telegram(f"❌ Network error while refreshing token for @{username}: {str(e)}")
        return None, None
    except Exception as e:
        send_message_via_telegram(f"❌ Unexpected error while refreshing token for @{username}: {str(e)}")
        return None, None
