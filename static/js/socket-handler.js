// Socket.IO initialization and event handling
document.addEventListener('DOMContentLoaded', function() {
    // Get socket room from data attribute
    var socketConfig = document.getElementById('socket-config');
    var socketRoom = socketConfig ? socketConfig.getAttribute('data-socket-room') || '' : '';
    
    // Only initialize if we have a socket room
    if (socketRoom) {
        var socket;
        var reconnectAttempts = 0;
        var maxReconnectAttempts = 5;
        var isConnected = false;
        
        function initializeSocket() {
            socket = io({
                reconnection: true,
                reconnectionAttempts: maxReconnectAttempts,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000,
                timeout: 20000
            });

            // Connection established
            socket.on('connect', function() {
                console.log('Connected to WebSocket server');
                isConnected = true;
                reconnectAttempts = 0;
                
                // Join user's room if socket_room is available
                if (socketRoom) {
                    socket.emit('join', {room: socketRoom});
                }
                
                // Show connection status to user
                if (typeof toastr !== 'undefined') {
                    toastr.success('Connected to real-time updates', 'Connected', {timeOut: 3000});
                }
            });

            // Connection error handling
            socket.on('connect_error', function(error) {
                console.error('Connection error:', error);
                isConnected = false;
                
                if (reconnectAttempts > 0 && typeof toastr !== 'undefined') {
                    var remaining = maxReconnectAttempts - reconnectAttempts;
                    toastr.warning('Connection lost. Reconnecting... (' + remaining + ' attempts left)', 'Connection Issue', {timeOut: 5000});
                }
            });

            // Reconnection handling
            socket.on('reconnect_attempt', function() {
                reconnectAttempts++;
                console.log('Reconnection attempt ' + reconnectAttempts + ' of ' + maxReconnectAttempts);
            });

            // Handle balance updates
            socket.on('balance_update', function(data) {
                console.log('Balance update received:', data);
                
                // Update the balance in the UI
                var balanceElement = document.querySelector('.account-balance[data-account="' + data.account_number + '"]');
                if (balanceElement) {
                    balanceElement.textContent = '₹' + data.new_balance.toLocaleString('en-IN');
                    
                    // Add visual feedback
                    balanceElement.classList.add('text-success');
                    setTimeout(function() {
                        balanceElement.classList.remove('text-success');
                    }, 1000);
                }
                
                // Update total balance if it exists
                var totalBalanceElement = document.getElementById('total-balance');
                if (totalBalanceElement) {
                    // Trigger a small animation to indicate update
                    totalBalanceElement.classList.add('text-success');
                    setTimeout(function() {
                        totalBalanceElement.classList.remove('text-success');
                    }, 1000);
                    
                    // Reload the page to update all balances
                    location.reload();
                }
            });

            // Handle new transaction notifications
            socket.on('new_transaction', function(data) {
                if (typeof toastr !== 'undefined') {
                    toastr.info(data.message, 'New Transaction', {timeOut: 10000});
                }
                
                // Refresh transactions list if on dashboard
                if (window.location.pathname === '/dashboard') {
                    location.reload();
                }
            });

            // Handle disconnect
            socket.on('disconnect', function(reason) {
                isConnected = false;
                if (reason === 'io server disconnect') {
                    // Server explicitly closed the connection
                    console.log('Disconnected by server:', reason);
                    if (typeof toastr !== 'undefined') {
                        toastr.error('Disconnected from server. Please refresh the page.', 'Disconnected');
                    }
                } else {
                    console.log('Disconnected:', reason);
                }
            });

            return socket;
        }

        // Initialize the socket connection
        initializeSocket();
    }
});
