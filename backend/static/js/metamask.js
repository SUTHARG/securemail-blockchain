/**
 * SecureMailScope - Client-Side MetaMask & Smart Contract Inspector (Read-Only)
 *
 * Safety Guarantees:
 * 1. Read-only only: strictly uses eth_call, eth_getCode, eth_chainId, eth_accounts.
 * 2. Never requests private keys, mnemonics, passwords, or transaction signatures.
 * 3. Never initiates on-chain transactions from the user's wallet.
 * 4. All dependencies are locally hosted - zero external CDN calls.
 */

(function () {
  'use strict';

  // Network dictionary for readable chain names
  const KNOWN_NETWORKS = {
    1: 'Ethereum Mainnet',
    5: 'Goerli Testnet',
    11155111: 'Sepolia Testnet',
    17000: 'Holesky Testnet',
    1337: 'Localhost / Geth',
    31337: 'Hardhat Local',
  };

  const CASE_STATES = [
    'None',
    'Opened',
    'Claimed',
    'Committing',
    'Revealing',
    'Finalized',
    'Disputed',
    'Expired',
    'Rejected',
  ];

  function getNetworkName(chainId) {
    const id = parseInt(chainId, 10);
    return KNOWN_NETWORKS[id] || `Chain ID ${id}`;
  }

  function formatAddress(addr) {
    if (!addr || typeof addr !== 'string') return '';
    if (addr.length < 10) return addr;
    return addr.slice(0, 6) + '...' + addr.slice(-4);
  }

  function parseHexChainId(chainIdHex) {
    if (typeof chainIdHex === 'number') return chainIdHex;
    if (typeof chainIdHex === 'string') {
      return parseInt(chainIdHex, chainIdHex.startsWith('0x') ? 16 : 10);
    }
    return 0;
  }

  class MetaMaskInspector {
    constructor(config) {
      this.config = config || {};
      this.expectedChainId = parseInt(this.config.chainId || 31337, 10);
      this.expectedNetwork = this.config.network || 'localhost';
      this.rpcUrl = this.config.rpcUrl || 'http://127.0.0.1:8545';
      this.contracts = this.config.contracts || {};
      this.caseInfo = this.config.case || {};

      this.currentAccount = null;
      this.currentChainId = null;
      this.isConnecting = false;

      this.elements = {};
    }

    init() {
      this.bindElements();
      if (!this.elements.card) return;

      this.renderInitialUI();
      if (!this.checkMetaMaskAvailability()) return;
      this.attachEventListeners();
      // Verification submits a normal form and reloads this page. Restore an
      // already-approved account with eth_accounts (which does not open a
      // permission popup); keep the explicit Connect button for first-time access.
      this.restoreAuthorizedConnection();
    }

    bindElements() {
      this.elements = {
        card: document.getElementById('metamask-card'),
        connectBtn: document.getElementById('mm-connect-btn'),
        connectBtnText: document.getElementById('mm-connect-btn-text'),
        disconnectBtn: document.getElementById('mm-disconnect-btn'),
        switchNetworkBtn: document.getElementById('mm-switch-network-btn'),
        statusBadge: document.getElementById('mm-status-badge'),
        addressDisplay: document.getElementById('mm-address-display'),
        networkDisplay: document.getElementById('mm-network-display'),
        providerDisplay: document.getElementById('mm-provider-display'),
        alertBox: document.getElementById('mm-alert-box'),
        caseState: document.getElementById('mm-case-state'),
        caseOnchainId: document.getElementById('mm-case-onchain-id'),
        casePcapHash: document.getElementById('mm-case-pcap-hash'),
        caseFinalRoot: document.getElementById('mm-case-final-root'),
        caseReportHash: document.getElementById('mm-case-report-hash'),
      };
    }

    renderInitialUI() {
      this.setStatus('DISCONNECTED', 'info');
      if (this.elements.addressDisplay) {
        this.elements.addressDisplay.textContent = 'Not connected';
      }
      if (this.elements.networkDisplay) {
        this.elements.networkDisplay.innerHTML = `<span style="color: var(--text-muted);">Not connected</span>`;
      }
    }

    checkMetaMaskAvailability() {
      const hasEthereum = typeof window !== 'undefined' && typeof window.ethereum !== 'undefined';
      if (!hasEthereum) {
        this.setStatus('METAMASK NOT DETECTED', 'fail');
        if (this.elements.providerDisplay) {
          this.elements.providerDisplay.innerHTML =
            '<span style="color: var(--fail);">MetaMask is not installed in this browser</span>';
        }
        this.showAlert(
          'MetaMask extension was not detected. Please install MetaMask from <a href="https://metamask.io" target="_blank" style="color: #58a6ff; text-decoration: underline;">metamask.io</a> to connect your wallet.',
          'fail'
        );
        return false;
      }

      if (this.elements.providerDisplay) {
        const isEthersAvailable = typeof window.ethers !== 'undefined';
        this.elements.providerDisplay.innerHTML =
          `<span style="color: var(--pass);">Ready</span> &bull; Provider detected ` +
          `(${isEthersAvailable ? 'ethers.js v6 ready' : 'EIP-1193 JSON-RPC ready'})`;
      }
      return true;
    }

    attachEventListeners() {
      if (this.elements.connectBtn) {
        this.elements.connectBtn.addEventListener('click', () => this.connectWallet());
      }

      if (this.elements.disconnectBtn) {
        this.elements.disconnectBtn.addEventListener('click', () => this.disconnectWallet());
      }

      if (this.elements.switchNetworkBtn) {
        this.elements.switchNetworkBtn.addEventListener('click', () => this.switchNetwork());
      }

      if (typeof window.ethereum !== 'undefined') {
        window.ethereum.on('accountsChanged', (accounts) => {
          this.handleAccountsChanged(accounts);
        });

        window.ethereum.on('chainChanged', (chainIdHex) => {
          this.handleChainChanged(chainIdHex);
        });

        window.ethereum.on('disconnect', (error) => {
          this.handleDisconnect(error);
        });
      }
    }

    async restoreAuthorizedConnection() {
      if (typeof window.ethereum === 'undefined') return;

      try {
        if (window.sessionStorage?.getItem('securemailscope.walletDisconnected') === '1') return;
        const accounts = await window.ethereum.request({ method: 'eth_accounts' });
        if (accounts && accounts.length > 0) {
          await this.handleAccountsChanged(accounts);
        }
      } catch (err) {
        // Keep the page usable if the wallet is locked or its provider is
        // temporarily unavailable. The user can explicitly reconnect.
        console.warn('Could not restore the previously approved MetaMask account:', err);
      }
    }

    async connectWallet() {
      if (!this.checkMetaMaskAvailability()) {
        return;
      }

      try {
        window.sessionStorage?.removeItem('securemailscope.walletDisconnected');
      } catch (_) {
        // Session storage may be unavailable; wallet connection can still proceed.
      }

      this.isConnecting = true;
      this.setStatus('CONNECTING...', 'pending');
      if (this.elements.connectBtn) {
        this.elements.connectBtn.disabled = true;
      }
      if (this.elements.connectBtnText) {
        this.elements.connectBtnText.textContent = 'Connecting...';
      }
      this.hideAlert();

      try {
        const accounts = await window.ethereum.request({
          method: 'eth_requestAccounts',
        });

        await this.handleAccountsChanged(accounts);
      } catch (err) {
        this.isConnecting = false;
        if (this.elements.connectBtn) {
          this.elements.connectBtn.disabled = false;
        }
        if (this.elements.connectBtnText) {
          this.elements.connectBtnText.textContent = 'Connect MetaMask';
        }

        if (err.code === 4001) {
          // User rejected the request in MetaMask popup
          this.setStatus('REJECTED', 'fail');
          this.showAlert(
            'Connection request was rejected in MetaMask. Click "Connect MetaMask" whenever you are ready to approve.',
            'pending'
          );
        } else if (err.code === -32002) {
          // Request already pending in MetaMask
          this.setStatus('PENDING APPROVAL', 'pending');
          this.showAlert(
            'A MetaMask connection request is already open in your browser extension. Please open MetaMask and click "Connect".',
            'pending'
          );
        } else {
          this.setStatus('ERROR', 'fail');
          this.showAlert(
            'Failed to connect to MetaMask: ' + (err.message || String(err)),
            'fail'
          );
        }
      }
    }

    async handleAccountsChanged(accounts) {
      this.isConnecting = false;
      if (this.elements.connectBtn) {
        this.elements.connectBtn.disabled = false;
      }
      if (this.elements.connectBtnText) {
        this.elements.connectBtnText.textContent = 'Connect MetaMask';
      }

      if (!accounts || accounts.length === 0) {
        this.currentAccount = null;
        this.setStatus('DISCONNECTED', 'info');
        if (this.elements.addressDisplay) {
          this.elements.addressDisplay.textContent = 'Not connected';
        }
        if (this.elements.connectBtn) this.elements.connectBtn.style.display = 'inline-flex';
        if (this.elements.disconnectBtn) this.elements.disconnectBtn.style.display = 'none';
        if (this.elements.switchNetworkBtn) this.elements.switchNetworkBtn.style.display = 'none';
        this.resetContractStatus();
        return;
      }

      this.currentAccount = accounts[0];
      if (this.elements.addressDisplay) {
        this.elements.addressDisplay.innerHTML = `
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap;">
            <span style="color: #58a6ff; font-weight: 600;">${this.currentAccount}</span>
            <button type="button" class="btn btn-secondary" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="navigator.clipboard.writeText('${this.currentAccount}'); this.innerText='Copied!'; setTimeout(() => this.innerText='Copy', 1500);">Copy</button>
          </div>
        `;
      }

      if (this.elements.connectBtn) this.elements.connectBtn.style.display = 'none';
      if (this.elements.disconnectBtn) this.elements.disconnectBtn.style.display = 'inline-flex';

      try {
        const chainIdHex = await window.ethereum.request({ method: 'eth_chainId' });
        await this.handleChainChanged(chainIdHex);
      } catch (err) {
        this.showAlert('Could not read chain ID from MetaMask: ' + (err.message || String(err)), 'fail');
      }
    }

    async handleChainChanged(chainIdHex) {
      const chainId = parseHexChainId(chainIdHex);
      this.currentChainId = chainId;
      const networkName = getNetworkName(chainId);

      if (this.elements.networkDisplay) {
        this.elements.networkDisplay.innerHTML = `
          <strong style="color: #fff;">${networkName}</strong>
          <span class="mono" style="color: var(--text-muted); font-size: 0.85rem;">(Chain ID: ${chainId})</span>
        `;
      }

      const isCorrectNetwork = (chainId === this.expectedChainId);

      if (!isCorrectNetwork) {
        this.setStatus('WRONG NETWORK', 'fail');
        if (this.elements.switchNetworkBtn) {
          this.elements.switchNetworkBtn.style.display = 'inline-flex';
          this.elements.switchNetworkBtn.textContent = `Switch to ${this.expectedNetwork} (${this.expectedChainId})`;
        }
        this.showAlert(
          `⚠️ <strong>Wrong Network:</strong> MetaMask is connected to <strong>${networkName}</strong> (Chain ID: <code>${chainId}</code>), but smart contracts are deployed on <strong>${this.expectedNetwork}</strong> (Chain ID: <code>${this.expectedChainId}</code>). Click "Switch to ${this.expectedNetwork}" to switch.`,
          'fail'
        );
        this.markContractsWrongNetwork();
      } else {
        this.setStatus('CONNECTED (READ-ONLY)', 'pass');
        if (this.elements.switchNetworkBtn) {
          this.elements.switchNetworkBtn.style.display = 'none';
        }
        this.showAlert(
          `✅ <strong>Connected:</strong> Wallet active on <strong>${networkName}</strong> (Chain ID: <code>${chainId}</code>). Read-only smart contract inspection active.`,
          'pass'
        );
        await this.inspectOnChain();
      }
    }

    handleDisconnect(error) {
      this.setStatus('RPC DISCONNECTED', 'fail');
      if (this.elements.providerDisplay) {
        this.elements.providerDisplay.innerHTML = `<span style="color: var(--fail);">RPC disconnected: ${error ? (error.message || error) : 'Connection lost'}</span>`;
      }
      this.showAlert(
        `MetaMask lost connection to RPC: ${error ? (error.message || String(error)) : 'Disconnected'}. Check if your local node is running at ${this.rpcUrl}.`,
        'fail'
      );
      this.resetContractStatus();
    }

    disconnectWallet() {
      try {
        window.sessionStorage?.setItem('securemailscope.walletDisconnected', '1');
      } catch (_) {
        // Session storage may be unavailable; reset the current page regardless.
      }
      this.currentAccount = null;
      this.currentChainId = null;
      this.renderInitialUI();
      if (this.elements.connectBtn) this.elements.connectBtn.style.display = 'inline-flex';
      if (this.elements.disconnectBtn) this.elements.disconnectBtn.style.display = 'none';
      if (this.elements.switchNetworkBtn) this.elements.switchNetworkBtn.style.display = 'none';
      this.hideAlert();
      this.resetContractStatus();
    }

    async switchNetwork() {
      if (typeof window.ethereum === 'undefined') return;

      const chainIdHex = '0x' + this.expectedChainId.toString(16);
      this.hideAlert();

      try {
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: chainIdHex }],
        });
      } catch (switchError) {
        // Error code 4902 indicates that the chain has not been added to MetaMask
        if (switchError.code === 4902 || switchError.code === -32603) {
          try {
            await window.ethereum.request({
              method: 'wallet_addEthereumChain',
              params: [
                {
                  chainId: chainIdHex,
                  chainName: this.expectedNetwork === 'localhost' ? 'Hardhat Local' : this.expectedNetwork,
                  rpcUrls: [this.rpcUrl || 'http://127.0.0.1:8545'],
                  nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
                },
              ],
            });
          } catch (addError) {
            this.showAlert('Could not add network to MetaMask: ' + (addError.message || String(addError)), 'fail');
          }
        } else if (switchError.code === 4001) {
          this.showAlert('Network switch was cancelled in MetaMask.', 'pending');
        } else {
          this.showAlert('Failed to switch network: ' + (switchError.message || String(switchError)), 'fail');
        }
      }
    }

    resetContractStatus() {
      const contractNames = ['CaseRegistry', 'ValidationQuorum', 'PostureLedger', 'Roles'];
      contractNames.forEach((cname) => {
        const el = document.getElementById(`mm-status-${cname}`);
        if (el) {
          el.innerHTML = '<span class="badge" style="background: rgba(139, 148, 158, 0.15); color: var(--text-muted);">Connect wallet to inspect</span>';
        }
      });
    }

    markContractsWrongNetwork() {
      const contractNames = ['CaseRegistry', 'ValidationQuorum', 'PostureLedger', 'Roles'];
      contractNames.forEach((cname) => {
        const el = document.getElementById(`mm-status-${cname}`);
        if (el) {
          el.innerHTML = '<span class="badge badge-fail">Wrong Network</span>';
        }
      });
    }

    async inspectOnChain() {
      if (typeof window.ethereum === 'undefined') return;

      // 1. Check bytecode presence for all configured contracts
      const contractNames = ['CaseRegistry', 'ValidationQuorum', 'PostureLedger', 'Roles'];

      for (const cname of contractNames) {
        const cdata = this.contracts[cname] || {};
        const addr = cdata.address;
        const statusEl = document.getElementById(`mm-status-${cname}`);
        if (!statusEl) continue;

        if (!addr || addr === '0x' || addr.length !== 42) {
          statusEl.innerHTML = '<span class="badge badge-fail">Unconfigured Address</span>';
          continue;
        }

        try {
          const code = await window.ethereum.request({
            method: 'eth_getCode',
            params: [addr, 'latest'],
          });

          if (code && code !== '0x' && code !== '0x0') {
            statusEl.innerHTML = '<span class="badge badge-pass">Deployed (Bytecode Present)</span>';
          } else {
            statusEl.innerHTML = '<span class="badge badge-fail">No Code at Address</span>';
          }
        } catch (err) {
          statusEl.innerHTML = `<span class="badge badge-fail">Check Error: ${err.message || 'RPC error'}</span>`;
        }
      }

      // 2. Read live on-chain case state if case has an onchain_case_id
      const onchainId = this.caseInfo.onchainCaseId;
      const regData = this.contracts.CaseRegistry || {};

      if (onchainId && onchainId.startsWith('0x') && onchainId.length === 66 && regData.address) {
        await this.queryLiveCaseRegistry(regData.address, regData.abi, onchainId);
      } else {
        if (this.elements.caseState && !this.caseInfo.onchainCaseId) {
          this.elements.caseState.innerHTML = `
            <span class="badge badge-pending">Not Opened On-Chain</span>
            <span style="color: var(--text-muted); font-size: 0.8rem; margin-left: 0.5rem;">(Off-chain local analysis complete)</span>
          `;
        }
      }
    }

    async queryLiveCaseRegistry(registryAddress, registryAbi, onchainCaseId) {
      try {
        // Preferred: ethers.js if loaded
        if (typeof window.ethers !== 'undefined' && registryAbi && registryAbi.length > 0) {
          const provider = new window.ethers.BrowserProvider(window.ethereum);
          const contract = new window.ethers.Contract(registryAddress, registryAbi, provider);

          // Call getCase view function
          const caseRecord = await contract.getCase(onchainCaseId);

          // caseRecord returns: [analyst, pcapHash, state, claimedRoot, finalRoot, contradicted, engineHash, rulesetHash, reportHash, openedAt, round]
          const rawState = Number(caseRecord.state !== undefined ? caseRecord.state : caseRecord[2]);
          const stateName = CASE_STATES[rawState] || `State #${rawState}`;
          const onchainPcap = caseRecord.pcapHash !== undefined ? caseRecord.pcapHash : caseRecord[1];
          const onchainFinalRoot = caseRecord.finalRoot !== undefined ? caseRecord.finalRoot : caseRecord[4];
          const onchainReportHash = caseRecord.reportHash !== undefined ? caseRecord.reportHash : caseRecord[8];

          if (this.elements.caseState) {
            this.elements.caseState.innerHTML = `
              <span class="badge badge-pass">${stateName}</span>
              <span style="font-size: 0.75rem; color: #58a6ff; margin-left: 0.4rem;">&bull; Live On-Chain</span>
            `;
          }

          if (this.elements.casePcapHash && onchainPcap && onchainPcap !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
            this.elements.casePcapHash.innerHTML = `
              <span style="color: #7ee787;">${onchainPcap}</span>
              <span style="font-size: 0.75rem; color: var(--pass); margin-left: 0.4rem;">✓ Verified On-Chain</span>
            `;
          }

          if (this.elements.caseFinalRoot && onchainFinalRoot && onchainFinalRoot !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
            this.elements.caseFinalRoot.innerHTML = `
              <span style="color: #7ee787;">${onchainFinalRoot}</span>
              <span style="font-size: 0.75rem; color: var(--pass); margin-left: 0.4rem;">✓ Quorum Finalized</span>
            `;
          }

          if (this.elements.caseReportHash && onchainReportHash && onchainReportHash !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
            this.elements.caseReportHash.innerHTML = `
              <span style="color: #7ee787;">${onchainReportHash}</span>
              <span style="font-size: 0.75rem; color: var(--pass); margin-left: 0.4rem;">✓ Custody Anchored</span>
            `;
          }
        } else {
          // Fallback: standard EIP-1193 eth_call with caseState(bytes32) selector: 0xa47071f4
          const callData = '0xa47071f4' + onchainCaseId.replace('0x', '');
          const resultHex = await window.ethereum.request({
            method: 'eth_call',
            params: [{ to: registryAddress, data: callData }, 'latest'],
          });

          const stateInt = parseInt(resultHex, 16);
          const stateName = CASE_STATES[stateInt] || `State #${stateInt}`;
          if (this.elements.caseState) {
            this.elements.caseState.innerHTML = `
              <span class="badge badge-pass">${stateName}</span>
              <span style="font-size: 0.75rem; color: #58a6ff; margin-left: 0.4rem;">&bull; Live RPC</span>
            `;
          }
        }
      } catch (err) {
        console.warn('Error reading on-chain case record:', err);
        if (this.elements.caseState) {
          this.elements.caseState.innerHTML = `
            <span class="badge badge-pending">${this.caseInfo.status || 'Pending'}</span>
            <span style="color: var(--text-muted); font-size: 0.8rem; margin-left: 0.4rem;">(Case not registered in connected contract)</span>
          `;
        }
      }
    }

    setStatus(text, type) {
      if (!this.elements.statusBadge) return;
      this.elements.statusBadge.textContent = text;
      this.elements.statusBadge.className = 'badge';

      if (type === 'pass') {
        this.elements.statusBadge.classList.add('badge-pass');
      } else if (type === 'fail') {
        this.elements.statusBadge.classList.add('badge-fail');
      } else if (type === 'pending') {
        this.elements.statusBadge.classList.add('badge-pending');
      } else {
        this.elements.statusBadge.style.background = 'rgba(139, 148, 158, 0.2)';
        this.elements.statusBadge.style.color = 'var(--text-muted)';
        this.elements.statusBadge.style.border = '1px solid var(--border)';
      }
    }

    showAlert(message, type) {
      if (!this.elements.alertBox) return;
      this.elements.alertBox.style.display = 'block';

      if (type === 'pass') {
        this.elements.alertBox.style.background = 'rgba(46, 160, 67, 0.12)';
        this.elements.alertBox.style.border = '1px solid var(--pass)';
        this.elements.alertBox.style.color = '#7ee787';
      } else if (type === 'fail') {
        this.elements.alertBox.style.background = 'rgba(248, 81, 73, 0.12)';
        this.elements.alertBox.style.border = '1px solid var(--fail)';
        this.elements.alertBox.style.color = '#ff7b72';
      } else if (type === 'pending') {
        this.elements.alertBox.style.background = 'rgba(210, 153, 34, 0.12)';
        this.elements.alertBox.style.border = '1px solid var(--pending)';
        this.elements.alertBox.style.color = '#e3b341';
      } else {
        this.elements.alertBox.style.background = 'rgba(56, 139, 253, 0.12)';
        this.elements.alertBox.style.border = '1px solid #388bfd';
        this.elements.alertBox.style.color = '#58a6ff';
      }

      this.elements.alertBox.innerHTML = message;
    }

    hideAlert() {
      if (!this.elements.alertBox) return;
      this.elements.alertBox.style.display = 'none';
      this.elements.alertBox.innerHTML = '';
    }
  }

  // Auto-initialize when DOM is ready
  function autoInit() {
    const configEl = document.getElementById('chain-client-config');
    let config = {};
    if (configEl) {
      try {
        config = JSON.parse(configEl.textContent);
      } catch (e) {
        console.error('Failed to parse chain-client-config JSON', e);
      }
    }

    const inspector = new MetaMaskInspector(config);
    inspector.init();

    // Expose for debugging and automated testing
    window.SecureMailMetaMask = {
      inspector,
      MetaMaskInspector,
      getNetworkName,
      parseHexChainId,
      formatAddress,
      CASE_STATES,
      KNOWN_NETWORKS,
    };
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoInit);
  } else {
    autoInit();
  }
})();
