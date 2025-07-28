// Function to initialize the UPI payment form
function initUPIForm() {
    const upiInput = document.getElementById('upi_id');
    const userList = document.getElementById('userList');
    
    if (!upiInput || !userList) return;
    
    // Function to show user list
    function showUserList() {
        userList.style.display = 'block';
    }
    
    // Function to hide user list
    function hideUserList() {
        userList.style.display = 'none';
    }
    
    // Show user list on input focus
    upiInput.addEventListener('focus', showUserList);
    
    // Hide user list when clicking outside
    document.addEventListener('click', function(e) {
        if (e.target !== upiInput && e.target !== userList && !userList.contains(e.target)) {
            hideUserList();
        }
    });
    
    // Filter users based on input
    upiInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const userItems = document.querySelectorAll('.user-item');
        let hasVisibleItems = false;
        
        userItems.forEach(function(item) {
            const userName = item.querySelector('.user-name')?.textContent?.toLowerCase() || '';
            const userEmail = item.querySelector('.user-upi')?.textContent?.toLowerCase() || '';
            
            if (userName.includes(searchTerm) || userEmail.includes(searchTerm)) {
                item.style.display = 'flex';
                hasVisibleItems = true;
            } else {
                item.style.display = 'none';
            }
        });
        
        // Show/hide user list based on search results
        userList.style.display = hasVisibleItems ? 'block' : 'none';
    });
    
    // Handle user selection from the list using event delegation
    document.addEventListener('click', function(e) {
        // Check if a user item was clicked
        const userItem = e.target.closest('.user-item');
        if (userItem) {
            e.preventDefault();
            const upi = userItem.getAttribute('data-upi');
            const name = userItem.getAttribute('data-name');
            
            // Set the UPI input value
            upiInput.value = upi;
            
            // Hide the user list
            userList.style.display = 'none';
            
            // Remove highlight from all items
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('selected');
            });
            
            // Highlight the selected user
            userItem.classList.add('selected');
            
            // Focus back on the input
            upiInput.focus();
        }
    });
}

// Initialize the form when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', initUPIForm);
