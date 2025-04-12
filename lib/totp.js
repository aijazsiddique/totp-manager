/**
 * TOTP.js - A simple wrapper around the jsOTP library
 */

class TOTPGenerator {
    constructor() {
      this.timeStep = 30; // Default time step in seconds
      this.codeLength = 6; // Default code length
    }
    
    /**
     * Generate a TOTP code from a base32 encoded secret
     * @param {string} secret - Base32 encoded secret
     * @returns {string} TOTP code
     */
    generate(secret) {
      try {
        // Clean the secret (remove spaces and convert to uppercase)
        const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
        
        // Create TOTP instance
        const totp = new TOTP(cleanSecret);
        
        // Generate code
        return totp.generate();
      } catch (error) {
        console.error('Error generating TOTP:', error);
        return '------';
      }
    }
    
    /**
     * Calculate seconds remaining until the next TOTP refresh
     * @returns {number} Seconds remaining
     */
    getRemainingSeconds() {
      const now = Math.floor(Date.now() / 1000);
      return this.timeStep - (now % this.timeStep);
    }
    
    /**
     * Calculate percentage of time remaining for current TOTP code
     * @returns {number} Percentage remaining (0-100)
     */
    getRemainingPercentage() {
      const remaining = this.getRemainingSeconds();
      return (remaining / this.timeStep) * 100;
    }
  }
  
  // Create a global TOTP instance
  const totpGenerator = new TOTPGenerator();
