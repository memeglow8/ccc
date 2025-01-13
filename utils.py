import base64
import hashlib
import os
import string
import random
from database import get_all_tokens
from telegram import send_message_via_telegram
from twitter import post_tweet
import time

def generate_code_verifier_and_challenge():
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

def generate_random_string(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def handle_post_single(tweet_text):
    tokens = get_all_tokens()
    if tokens:
        access_token, refresh_token, username, last_refresh = tokens[0]
        result = post_tweet(access_token, tweet_text)
        send_message_via_telegram(f"📝 Tweet posted with @{username}: {result}")
    else:
        send_message_via_telegram("❌ No tokens found to post a tweet.")

def handle_post_bulk(message, min_delay, max_delay):
    tokens = get_all_tokens()
    parts = message.split(' ', 1)
    
    if len(parts) < 2:
        send_message_via_telegram("❌ Incorrect format. Use `/post_bulk <tweet content>`.")
        return

    base_tweet_text = parts[1]
    
    if not tokens:
        send_message_via_telegram("❌ No tokens found to post tweets.")
        return
    
    for token_data in tokens:
        access_token, refresh_token, username, last_refresh = token_data
        random_suffix = generate_random_string(10)
        tweet_text = f"{base_tweet_text} {random_suffix}"
        
        result = post_tweet(access_token, tweet_text)
        delay = random.randint(min_delay, max_delay)
        
        send_message_via_telegram(
            f"📝 Tweet posted with @{username}: {result}\n"
            f"⏱ Delay before next post: {delay} seconds."
        )
        
        time.sleep(delay)
    
    send_message_via_telegram(f"✅ Bulk tweet posting complete. {len(tokens)} tweets posted.")
