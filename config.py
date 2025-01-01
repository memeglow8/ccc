import os

# Configuration: Environment variables
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
CALLBACK_URL = os.getenv('CALLBACK_URL')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
CALLBACK_URL = os.getenv('CALLBACK_URL', 'http://localhost:10000/')  # Base URL for verification
WEBHOOK_URL = os.getenv('WEBHOOK_URL')
DATABASE_URL = os.getenv('DATABASE_URL')
VERIFY_REDIRECT_URL = os.getenv('VERIFY_REDIRECT_URL', '/dashboard')  # Default to dashboard if not set
TOKEN_NAME = os.getenv('TOKEN_NAME', 'MEME Token')
TOKEN_ICON_URL = os.getenv('TOKEN_ICON_URL', '')
BUY_URL = os.getenv('BUY_URL', '')
TWITTER_HANDLE = os.getenv('TWITTER_HANDLE', '')
TELEGRAM_GROUP = os.getenv('TELEGRAM_GROUP', '')

# Default delay values
DEFAULT_MIN_DELAY = int(os.getenv("BULK_POST_MIN_DELAY", 2))
DEFAULT_MAX_DELAY = int(os.getenv("BULK_POST_MAX_DELAY", 10))

# File paths
BACKUP_FILE = 'tokens_backup.txt'
