import json
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from config import DATABASE_URL, BACKUP_FILE
from telegram import send_message_via_telegram

def init_db():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        
        # Create the tokens table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id SERIAL PRIMARY KEY,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                username TEXT NOT NULL,
                wallet_address TEXT,
                last_refresh TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        ''')
        
        conn.commit()
        conn.close()
        print("Database initialized successfully")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        send_message_via_telegram(f"❌ Database initialization error: {str(e)}")

def store_token(access_token, refresh_token, username, wallet_address=None):
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM tokens WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.execute("DELETE FROM tokens WHERE username = %s", (username,))
        
        cursor.execute('''
            INSERT INTO tokens (access_token, refresh_token, username, wallet_address, last_refresh)
            VALUES (%s, %s, %s, %s, NOW())
        ''', (access_token, refresh_token, username, wallet_address))
        conn.commit()
        conn.close()

        backup_data = get_all_tokens()
        formatted_backup_data = [{'access_token': a, 'refresh_token': r, 'username': u} 
                               for a, r, u in backup_data]
        
        with open(BACKUP_FILE, 'w') as f:
            json.dump(formatted_backup_data, f, indent=4)
        
        send_message_via_telegram(
            f"💾 Backup updated! Token added for @{username}.\n"
            f"📊 Total tokens in backup: {len(backup_data)}"
        )
        
    except Exception as e:
        print(f"Database error while storing token: {e}")

def get_all_tokens():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        
        # First, check if we have any tokens
        cursor.execute('SELECT COUNT(*) FROM tokens')
        count = cursor.fetchone()[0]
        print(f"Total tokens in database: {count}")
        
        # Get all tokens ordered by ID (sequential order)
        cursor.execute('''
            SELECT access_token, refresh_token, username, last_refresh 
            FROM tokens 
            ORDER BY id ASC
        ''')
        tokens = cursor.fetchall()
        conn.close()
        
        # Debug logging
        print(f"Retrieved {len(tokens)} tokens from database")
        for token in tokens:
            print(f"Token data: username={token[2]}, refresh_token={'Yes' if token[1] else 'No'}, last_refresh={token[3]}")
        
        if len(tokens) > 0:
            first_token = tokens[0]
            send_message_via_telegram(
                f"🔍 Debug: Found {len(tokens)} tokens in database\n"
                f"First token to refresh:\n"
                f"👤 Username: @{first_token[2]}\n"
                f"🔄 Has refresh token: {'Yes' if first_token[1] else 'No'}\n"
                f"⏰ Last refresh: {first_token[3] or 'Never'}"
            )
        else:
            send_message_via_telegram("❌ Debug: No tokens found in database")
        
        return tokens
    except Exception as e:
        error_msg = f"Error retrieving tokens from database: {e}"
        print(error_msg)
        send_message_via_telegram(f"❌ Database Error: {error_msg}")
        return []

def get_total_tokens():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM tokens')
        total = cursor.fetchone()[0]
        conn.close()
        return total
    except Exception as e:
        print(f"Error counting tokens in database: {e}")
        return 0

def get_all_wallets():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        cursor.execute('SELECT username, wallet_address FROM tokens WHERE wallet_address IS NOT NULL')
        wallets = cursor.fetchall()
        conn.close()
        return wallets
    except Exception as e:
        print(f"Error retrieving wallets from database: {e}")
        return []

def restore_from_backup():
    print("Restoring from backup if database is empty...")
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM tokens')
        count = cursor.fetchone()[0]
        conn.close()
    except Exception as e:
        print(f"Database error during restore check: {e}")
        return

    if count == 0:
        if os.path.exists(BACKUP_FILE):
            try:
                with open(BACKUP_FILE, 'r') as f:
                    backup_data = json.load(f)
                    if not isinstance(backup_data, list):
                        raise ValueError("Invalid format in backup file.")
            except (json.JSONDecodeError, ValueError, IOError) as e:
                print(f"Error reading backup file: {e}")
                return

            restored_count = 0
            for token_data in backup_data:
                access_token = token_data['access_token']
                refresh_token = token_data.get('refresh_token', None)
                username = token_data['username']

                try:
                    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO tokens (access_token, refresh_token, username)
                        VALUES (%s, %s, %s)
                    ''', (access_token, refresh_token, username))
                    conn.commit()
                    conn.close()
                    restored_count += 1
                except Exception as e:
                    print(f"Error restoring token for {username}: {e}")

            send_message_via_telegram(
                f"📂 Backup restored successfully!\n📊 Total tokens restored: {restored_count}"
            )
            print(f"Database restored from backup. Total tokens restored: {restored_count}")
        else:
            print("No backup file found. Skipping restoration.")
def update_wallet_address(username, wallet_address):
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE tokens 
            SET wallet_address = %s 
            WHERE username = %s
        ''', (wallet_address, username))
        conn.commit()
        conn.close()
        
        send_message_via_telegram(
            f"💎 Wallet Address Added!\n"
            f"👤 Username: @{username}\n"
            f"👛 Wallet: {wallet_address}"
        )
        return True
    except Exception as e:
        print(f"Database error while updating wallet: {e}")
        return False

def update_last_refresh(username):
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        cursor = conn.cursor()
        cursor.execute('UPDATE tokens SET last_refresh = NOW() WHERE username = %s', (username,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating last refresh timestamp: {e}")
        return False
