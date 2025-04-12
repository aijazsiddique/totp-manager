document.addEventListener('DOMContentLoaded', () => {
    // DOM elements
    const accountsContainer = document.getElementById('accounts-container');
    const addAccountBtn = document.getElementById('add-account-btn');
    const addAccountForm = document.getElementById('add-account-form');
    const saveAccountBtn = document.getElementById('save-account-btn');
    const cancelAccountBtn = document.getElementById('cancel-account-btn');
    const accountNameInput = document.getElementById('account-name');
    const totpSecretInput = document.getElementById('totp-secret');
    const statusMessage = document.getElementById('status-message');
    
    // State
    let accounts = [];
    let totpUpdateInterval;
    
    // Load accounts from storage and initialize UI
    loadAccounts();
    
    // Event listeners
    addAccountBtn.addEventListener('click', showAddAccountForm);
    saveAccountBtn.addEventListener('click', saveAccount);
    cancelAccountBtn.addEventListener('click', hideAddAccountForm);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !addAccountForm.classList.contains('hidden')) {
        hideAddAccountForm();
      } else if (e.key === 'Enter' && !addAccountForm.classList.contains('hidden')) {
        saveAccount();
      }
    });
    
    /**
     * Load accounts from Chrome storage
     */
    function loadAccounts() {
      chrome.storage.sync.get('totpAccounts', (result) => {
        accounts = result.totpAccounts || [];
        renderAccounts();
        startTotpUpdateInterval();
      });
    }
    
    /**
     * Save accounts to Chrome storage
     */
    function saveAccounts() {
      chrome.storage.sync.set({ 'totpAccounts': accounts }, () => {
        console.log('Accounts saved successfully');
      });
    }
    
    /**
     * Render account list
     */
    function renderAccounts() {
      accountsContainer.innerHTML = '';
      
      if (accounts.length === 0) {
        accountsContainer.innerHTML = '<div class="no-accounts">No accounts added yet. Click "Add New Account" to get started.</div>';
        return;
      }
      
      accounts.forEach((account, index) => {
        try {
          const totpCode = totpGenerator.generate(account.secret);
          const remainingPercentage = totpGenerator.getRemainingPercentage();
          
          const accountElement = document.createElement('div');
          accountElement.className = 'account-item';
          accountElement.innerHTML = `
            <div class="account-info">
              <div class="account-name">${account.name}</div>
            </div>
            <div class="account-actions">
              <span class="totp-code" data-index="${index}" data-secret="${account.secret}">${formatTotpCode(totpCode)}</span>
              <button class="delete-btn" data-index="${index}" title="Delete account">×</button>
            </div>
            <div class="time-remaining" style="width: ${remainingPercentage}%"></div>
          `;
          
          accountsContainer.appendChild(accountElement);
          
          // Add event listener to copy code on click
          const codeElement = accountElement.querySelector('.totp-code');
          codeElement.addEventListener('click', (e) => {
            const index = e.target.getAttribute('data-index');
            const secret = e.target.getAttribute('data-secret');
            const code = totpGenerator.generate(secret);
            copyToClipboard(code);
            
            // Visual feedback on copy
            e.target.style.backgroundColor = '#d1e7dd';
            e.target.style.color = '#0a3622';
            setTimeout(() => {
              e.target.style.backgroundColor = '';
              e.target.style.color = '';
            }, 300);
            
            showStatus(`Copied ${accounts[index].name} code!`);
          });
          
          // Add event listener to delete account
          const deleteBtn = accountElement.querySelector('.delete-btn');
          deleteBtn.addEventListener('click', (e) => {
            const index = e.target.getAttribute('data-index');
            
            if (confirm(`Are you sure you want to delete the "${accounts[index].name}" account?`)) {
              deleteAccount(index);
            }
            
            e.stopPropagation();
          });
        } catch (error) {
          console.error('Error rendering account:', error, account);
        }
      });
    }
    
    /**
     * Format TOTP code with a space in the middle (e.g., 123 456)
     */
    function formatTotpCode(code) {
      if (code.length === 6) {
        return `${code.substring(0, 3)} ${code.substring(3)}`;
      }
      return code;
    }
    
    /**
     * Start interval to update TOTP codes
     */
    function startTotpUpdateInterval() {
      if (totpUpdateInterval) {
        clearInterval(totpUpdateInterval);
      }
      
      // Update immediately
      updateRemainingTime();
      
      // Then update every second
      totpUpdateInterval = setInterval(updateRemainingTime, 1000);
    }
    
    /**
     * Update remaining time indicators
     */
    function updateRemainingTime() {
      const remainingPercentage = totpGenerator.getRemainingPercentage();
      const timeElements = document.querySelectorAll('.time-remaining');
      
      timeElements.forEach(element => {
        element.style.width = `${remainingPercentage}%`;
        
        // Change color when time is running out
        if (remainingPercentage < 20) {
          element.style.backgroundColor = '#ff4d4f';
        } else {
          element.style.backgroundColor = '';
        }
      });
      
      // If we're at 0%, refresh all codes
      if (remainingPercentage >= 99 || remainingPercentage <= 1) {
        setTimeout(() => {
          renderAccounts();
        }, 1000);
      }
    }
    
    /**
     * Show add account form
     */
    function showAddAccountForm() {
      addAccountForm.classList.remove('hidden');
      addAccountBtn.classList.add('hidden');
      accountNameInput.focus();
    }
    
    /**
     * Hide add account form
     */
    function hideAddAccountForm() {
      addAccountForm.classList.add('hidden');
      addAccountBtn.classList.remove('hidden');
      accountNameInput.value = '';
      totpSecretInput.value = '';
    }
    
    /**
     * Save new account
     */
    function saveAccount() {
      const name = accountNameInput.value.trim();
      const secret = totpSecretInput.value.trim().replace(/\s+/g, '').toUpperCase();
      
      if (!name) {
        showStatus('Please enter an account name', true);
        accountNameInput.focus();
        return;
      }
      
      if (!secret) {
        showStatus('Please enter a TOTP secret', true);
        totpSecretInput.focus();
        return;
      }
      
      try {
        // Test if the secret is valid by generating a code
        const testCode = totpGenerator.generate(secret);
        if (testCode === '------') {
          throw new Error('Invalid secret');
        }
        
        // Check for duplicate account names
        const duplicate = accounts.findIndex(account => account.name.toLowerCase() === name.toLowerCase());
        if (duplicate !== -1) {
          if (!confirm(`An account named "${name}" already exists. Replace it?`)) {
            return;
          }
          accounts.splice(duplicate, 1);
        }
        
        // Add the new account
        accounts.push({ name, secret });
        saveAccounts();
        renderAccounts();
        hideAddAccountForm();
        showStatus(`Added ${name} account!`);
      } catch (error) {
        console.error('Error saving account:', error);
        showStatus('Invalid TOTP secret key. Please check and try again.', true);
      }
    }
    
    /**
     * Delete account
     */
    function deleteAccount(index) {
      const accountName = accounts[index].name;
      accounts.splice(index, 1);
      saveAccounts();
      renderAccounts();
      showStatus(`Deleted ${accountName} account`);
    }
    
    /**
     * Copy text to clipboard
     */
    function copyToClipboard(text) {
      // Remove spaces for clipboard
      text = text.replace(/\s+/g, '');
      
      navigator.clipboard.writeText(text).catch(err => {
        console.error('Could not copy text: ', err);
      });
    }
    
    /**
     * Show status message
     */
    function showStatus(message, isError = false) {
      statusMessage.textContent = message;
      statusMessage.style.color = isError ? '#ff4d4f' : '#2683ff';
      statusMessage.style.opacity = 1;
      
      // Clear the message after 3 seconds
      setTimeout(() => {
        statusMessage.style.opacity = 0;
        setTimeout(() => {
          statusMessage.textContent = '';
        }, 300);
      }, 3000);
    }
  });