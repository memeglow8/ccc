// Random usernames and amounts for notifications
const usernames = [
    '@crypto_whale', '@token_lover', '@nft_collector', '@defi_master',
    '@blockchain_pro', '@eth_trader', '@web3_native', '@hodler',
    '@meta_trader', '@coin_master', '@nft_king', '@crypto_queen',
    '@blockchain_guru', '@defi_expert', '@token_hunter', '@crypto_sage',
    '@web3_pioneer', '@nft_artist', '@token_wizard', '@crypto_ninja'
];

const amounts = [
    '2,500', '3,750', '4,200', '5,100', '6,300', '7,450', '8,200', '9,100',
    '3,300', '4,600', '5,800', '6,900', '7,100', '8,400', '9,300', '4,800'
];

function showNotification() {
    const notification = document.getElementById('notification');
    const usernameElement = document.getElementById('notification-username');
    const randomUsername = usernames[Math.floor(Math.random() * usernames.length)];
    
    const randomAmount = amounts[Math.floor(Math.random() * amounts.length)];
    usernameElement.textContent = `${randomUsername} claimed $${randomAmount}`;
    notification.classList.add('show');
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3500); // Show notification for 3.5 seconds
}

// Initialize notifications
setTimeout(() => {
    showNotification();
    // Show notifications randomly every 5-8 seconds
    setInterval(() => {
        showNotification();
    }, Math.random() * 3000 + 5000);
}, 2000);
