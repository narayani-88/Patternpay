// GPay Payment Handler
class GPayHandler {
    constructor(hasUsers) {
        this.hasUsers = hasUsers;
        this.form = document.getElementById('gpayForm');
        this.upiInput = document.getElementById('upi_id');
        this.amountInput = document.getElementById('amount');
        this.payButton = document.getElementById('payButton');
        this.userList = document.getElementById('userList');
        
        this.initialize();
    }
    
    initialize() {
        if (!this.form) return;
        
        // Initialize user list visibility
        if (this.userList) {
            this.userList.style.display = 'none';
            
            // If there are no users, hide the user list container completely
            if (!this.hasUsers) {
                this.userList.style.display = 'none';
            }
        }
        
        // Initialize event listeners
        this.initializeEventListeners();
    }
    
    initializeEventListeners() {
        // UPI input focus/blur
        if (this.upiInput) {
            this.upiInput.addEventListener('focus', () => this.toggleUserList(true));
            this.upiInput.addEventListener('blur', () => setTimeout(() => this.toggleUserList(false), 200));
            this.upiInput.addEventListener('input', (e) => this.filterUserList(e.target.value));
        }
        
        // Form submission
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleFormSubmit(e));
        }
        
        // User list clicks
        if (this.userList) {
            this.userList.addEventListener('click', (e) => this.handleUserSelection(e));
        }
    }
    
    toggleUserList(show) {
        if (!this.userList || !this.hasUsers) return;
        this.userList.style.display = show ? 'block' : 'none';
    }
    
    filterUserList(searchTerm) {
        if (!this.userList) return;
        
        const searchValue = searchTerm.toLowerCase();
        const userItems = this.userList.querySelectorAll('.user-item');
        let hasVisibleItems = false;
        
        userItems.forEach(item => {
            const userName = item.querySelector('.user-name')?.textContent?.toLowerCase() || '';
            const userUpi = item.querySelector('.user-upi')?.textContent?.toLowerCase() || '';
            
            if (userName.includes(searchValue) || userUpi.includes(searchValue)) {
                item.style.display = 'flex';
                hasVisibleItems = true;
            } else {
                item.style.display = 'none';
            }
        });
        
        this.userList.style.display = hasVisibleItems ? 'block' : 'none';
    }
    
    handleUserSelection(event) {
        const userItem = event.target.closest('.user-item');
        if (!userItem || !this.upiInput) return;
        
        const upiId = userItem.getAttribute('data-upi');
        if (upiId) {
            this.upiInput.value = upiId;
            this.toggleUserList(false);
            if (this.amountInput) {
                this.amountInput.focus();
            }
        }
    }
    
    async handleFormSubmit(event) {
        event.preventDefault();
        if (!this.form || !this.payButton) return;
        
        // Store original button state
        const originalButtonText = this.payButton.innerHTML;
        this.payButton.disabled = true;
        this.payButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
        
        try {
            const formData = new FormData(this.form);
            const response = await fetch(this.form.action, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.handleSuccess(result);
            } else if (result.require_pin) {
                this.showPinModal();
            } else {
                this.handleError(result);
            }
        } catch (error) {
            console.error('Error:', error);
            this.showErrorModal('Failed to process payment. Please check your connection and try again.');
        } finally {
            // Reset button state
            if (this.payButton) {
                this.payButton.disabled = false;
                this.payButton.innerHTML = originalButtonText;
            }
        }
    }
    
    handleSuccess(result) {
        // Update balance if available
        const availableBalance = document.getElementById('availableBalance');
        if (availableBalance && result.data?.new_balance !== undefined) {
            availableBalance.textContent = parseFloat(result.data.new_balance).toFixed(2);
        }
        
        // Show success message
        const successMessage = document.getElementById('successMessage');
        const transactionDetails = document.getElementById('transactionDetails');
        
        if (successMessage && transactionDetails) {
            successMessage.textContent = 'Payment Successful!';
            transactionDetails.innerHTML = `
                <div class="alert alert-success">
                    <p class="mb-1">${result.message || 'Transaction completed successfully'}</p>
                    <p class="mb-0">Your new balance: ₹${parseFloat(availableBalance?.textContent || '0').toFixed(2)}</p>
                </div>
            `;
            
            // Show success modal
            const successModal = new bootstrap.Modal(document.getElementById('successModal'));
            successModal.show();
            
            // Reset form
            if (this.form) {
                this.form.reset();
            }
            
            // Redirect after delay
            setTimeout(() => {
                successModal.hide();
                if (window.location.pathname.includes('gpay_payment')) {
                    window.location.href = '/transactions';
                }
            }, 3000);
        }
    }
    
    handleError(result) {
        let errorMsg = result.error || result.message || 'An error occurred. Please try again.';
        
        // Add validation errors if available
        if (result.errors) {
            errorMsg += '<ul class="mt-2 mb-0">';
            for (const [field, errors] of Object.entries(result.errors)) {
                errorMsg += `<li>${field}: ${Array.isArray(errors) ? errors.join(', ') : errors}</li>`;
            }
            errorMsg += '</ul>';
        }
        
        this.showErrorModal(errorMsg);
    }
    
    showErrorModal(message) {
        const errorMessage = document.getElementById('errorMessage');
        if (errorMessage) {
            errorMessage.innerHTML = message;
            const errorModal = new bootstrap.Modal(document.getElementById('errorModal'));
            errorModal.show();
        }
    }
    
    showPinModal() {
        const pinModal = new bootstrap.Modal(document.getElementById('pinModal'));
        pinModal.show();
    }

    // Initialize PIN input handling
    initializePinInput() {
        const pinInput = document.getElementById('pinInput');
        if (pinInput) {
            pinInput.addEventListener('input', (e) => {
                e.target.value = e.target.value.replace(/[^0-9]/g, '').slice(0, 6);
                e.target.classList.remove('is-invalid');
            });
        }
        
        // Initialize PIN verification button
        const verifyPinBtn = document.getElementById('verifyPinBtn');
        if (verifyPinBtn) {
            verifyPinBtn.addEventListener('click', async () => {
                const pinInput = document.getElementById('pinInput');
                if (!pinInput) return;
                
                const pin = pinInput.value.trim();
                if (!/^\d{4,6}$/.test(pin)) {
                    this.showToast('error', 'Invalid PIN', 'Please enter a valid 4-6 digit PIN');
                    return;
                }
                
                const originalBtnText = verifyPinBtn.innerHTML;
                verifyPinBtn.disabled = true;
                verifyPinBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Verifying...';
                
                try {
                    const response = await fetch('/verify_pin', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({ pin })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        // If PIN is verified, submit the form
                        if (this.form) {
                            this.form.submit();
                        }
                    } else {
                        this.showToast('error', 'Verification Failed', result.message || 'Invalid PIN. Please try again.');
                        if (pinInput) {
                            pinInput.value = '';
                            pinInput.focus();
                        }
                    }
                } catch (error) {
                    console.error('Error:', error);
                    this.showToast('error', 'Error', 'Failed to verify PIN. Please try again.');
                } finally {
                    if (verifyPinBtn) {
                        verifyPinBtn.disabled = false;
                        verifyPinBtn.innerHTML = originalBtnText;
                    }
                }
            });
        }
    }
    
    // Show toast notification
    showToast(type, title, message) {
        const toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) return;
        
        const toast = document.createElement('div');
        toast.className = `toast bg-${type} text-white`;
        toast.role = 'alert';
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');
        
        toast.innerHTML = `
            <div class="toast-header">
                <strong class="me-auto">${title}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        `;
        
        toastContainer.appendChild(toast);
        
        // Initialize and show the toast
        const bsToast = new bootstrap.Toast(toast, {
            autohide: true,
            delay: 5000
        });
        
        bsToast.show();
        
        // Auto-remove toast after it's hidden
        toast.addEventListener('hidden.bs.toast', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Get hasUsers from data attribute
    const gpayContainer = document.getElementById('gpay-container');
    const hasUsers = gpayContainer ? gpayContainer.getAttribute('data-has-users') === 'true' : false;
    
    // Initialize GPay handler
    const gpayHandler = new GPayHandler(hasUsers);
    
    // Initialize PIN input handling
    gpayHandler.initializePinInput();
});
