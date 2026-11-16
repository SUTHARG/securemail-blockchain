/**
 * Automated UI State and Wrong-Network Test for SecureMailScope MetaMask Inspector.
 * Runs in Node.js, mocking DOM elements and EIP-1193 window.ethereum provider.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Mock DOM elements
class MockElement {
  constructor(id) {
    this.id = id;
    this.innerText = '';
    this.innerHTML = '';
    this.textContent = '';
    this.style = {};
    this.disabled = false;
    this.className = '';
    this.classList = {
      classes: new Set(),
      add: (c) => this.classList.classes.add(c),
      remove: (c) => this.classList.classes.delete(c),
      contains: (c) => this.classList.classes.has(c),
    };
    this.listeners = {};
  }

  addEventListener(event, fn) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(fn);
  }

  async trigger(event, data) {
    if (this.listeners[event]) {
      for (const fn of this.listeners[event]) {
        await fn(data);
      }
    }
  }
}

class MockDocument {
  constructor() {
    this.elements = {};
    this.listeners = {};
  }

  getElementById(id) {
    if (!this.elements[id]) {
      this.elements[id] = new MockElement(id);
    }
    return this.elements[id];
  }

  addEventListener(event, fn) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(fn);
  }
}

// Mock EIP-1193 Ethereum Provider
class MockEthereum {
  constructor(initialAccounts = [], initialChainId = '0x1') {
    this.accounts = initialAccounts;
    this.chainId = initialChainId;
    this.listeners = {};
    this.callHistory = [];
  }

  on(event, fn) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(fn);
  }

  async emit(event, ...args) {
    if (this.listeners[event]) {
      for (const fn of this.listeners[event]) {
        await fn(...args);
      }
    }
  }

  async request({ method, params }) {
    this.callHistory.push({ method, params });

    // Enforce Read-Only Safety - Never allow signing or transactions
    if (['eth_sendTransaction', 'eth_sign', 'personal_sign', 'eth_signTypedData'].includes(method)) {
      throw new Error(`SECURITY VIOLATION: Write/Signing method '${method}' called in read-only mode!`);
    }

    if (method === 'eth_requestAccounts') {
      if (this.rejectNextRequest) {
        const err = new Error('User rejected the request.');
        err.code = 4001;
        throw err;
      }
      return this.accounts;
    }

    if (method === 'eth_accounts') {
      return this.accounts;
    }

    if (method === 'eth_chainId') {
      return this.chainId;
    }

    if (method === 'wallet_switchEthereumChain') {
      const targetChain = params[0].chainId;
      this.chainId = targetChain;
      await this.emit('chainChanged', targetChain);
      return null;
    }

    if (method === 'eth_getCode') {
      const addr = params[0];
      // Return dummy bytecode for valid contract addresses
      if (addr && addr.startsWith('0x') && addr.length === 42) {
        return '0x608060405234801561001057600080fd5b50...';
      }
      return '0x';
    }

    if (method === 'eth_call') {
      // Return dummy state uint256 (e.g. State.Opened = 1)
      return '0x0000000000000000000000000000000000000000000000000000000000000001';
    }

    return null;
  }
}

async function runTests() {
  console.log('--- Starting MetaMask UI States & Wrong-Network Tests ---');

  // Load metamask.js source
  const scriptPath = path.resolve(__dirname, '../static/js/metamask.js');
  const scriptContent = fs.readFileSync(scriptPath, 'utf8');

  // Setup Global Environment
  const mockDoc = new MockDocument();
  global.document = mockDoc;
  global.window = {
    document: mockDoc,
    navigator: { clipboard: { writeText: async () => {} } },
  };

  // Mock initial config element
  const configEl = mockDoc.getElementById('chain-client-config');
  configEl.textContent = JSON.stringify({
    network: 'localhost',
    chainId: 31337,
    rpcUrl: 'http://127.0.0.1:8545',
    contracts: {
      CaseRegistry: { address: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512', abi: [] },
      ValidationQuorum: { address: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0', abi: [] },
      PostureLedger: { address: '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9', abi: [] },
      Roles: { address: '0x5FbDB2315678afecb367f032d93F642f64180aa3', abi: [] },
    },
    case: {
      caseId: 'test_case_123',
      onchainCaseId: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    },
  });

  // Evaluate script
  eval(scriptContent);
  assert(window.SecureMailMetaMask, 'window.SecureMailMetaMask must be defined');
  const { inspector, getNetworkName, parseHexChainId } = window.SecureMailMetaMask;

  console.log('✓ Script parsed and initialized successfully');

  // Test 1: Helper functions
  assert.strictEqual(getNetworkName(31337), 'Hardhat Local');
  assert.strictEqual(getNetworkName(1), 'Ethereum Mainnet');
  assert.strictEqual(getNetworkName(11155111), 'Sepolia Testnet');
  assert.strictEqual(parseHexChainId('0x7a69'), 31337);
  assert.strictEqual(parseHexChainId('0x1'), 1);
  console.log('✓ Network name and hex chain ID parsers verified');

  // Test 2: Missing MetaMask state
  inspector.elements = {};
  inspector.bindElements();
  inspector.checkMetaMaskAvailability();
  assert(mockDoc.getElementById('mm-status-badge').textContent.includes('NOT DETECTED'));
  assert(mockDoc.getElementById('mm-alert-box').innerHTML.includes('not detected'));
  console.log('✓ Missing MetaMask state handled cleanly');

  // Test 3: User rejects MetaMask popup (Error 4001)
  const mockEth = new MockEthereum(['0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'], '0x1');
  mockEth.rejectNextRequest = true;
  window.ethereum = mockEth;

  inspector.checkMetaMaskAvailability();
  inspector.attachEventListeners();
  await inspector.connectWallet();

  assert.strictEqual(mockDoc.getElementById('mm-status-badge').textContent, 'REJECTED');
  assert(mockDoc.getElementById('mm-alert-box').innerHTML.includes('Connection request was rejected'));
  console.log('✓ User rejection (Error 4001) handled with friendly guidance');

  // Test 4: Successful connection on WRONG NETWORK (Mainnet 0x1 vs Expected 31337)
  mockEth.rejectNextRequest = false;
  mockEth.chainId = '0x1'; // Chain 1 (Mainnet)
  await inspector.connectWallet();

  assert.strictEqual(mockDoc.getElementById('mm-status-badge').textContent, 'WRONG NETWORK');
  assert(mockDoc.getElementById('mm-status-badge').classList.contains('badge-fail'));
  assert(mockDoc.getElementById('mm-alert-box').innerHTML.includes('Wrong Network'));
  assert.strictEqual(mockDoc.getElementById('mm-switch-network-btn').style.display, 'inline-flex');
  assert(mockDoc.getElementById('mm-address-display').innerHTML.includes('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'));
  console.log('✓ Wrong-network condition correctly detected and flagged with Switch Network action');

  // Test 5: Switch network to correct chain (31337 / 0x7a69)
  await inspector.switchNetwork();

  assert.strictEqual(mockEth.chainId, '0x7a69');
  assert.strictEqual(mockDoc.getElementById('mm-status-badge').textContent, 'CONNECTED (READ-ONLY)');
  assert(mockDoc.getElementById('mm-status-badge').classList.contains('badge-pass'));
  assert.strictEqual(mockDoc.getElementById('mm-switch-network-btn').style.display, 'none');
  assert(mockDoc.getElementById('mm-alert-box').innerHTML.includes('Connected'));
  console.log('✓ Network switch successfully verified correct chain (31337)');

  // Test 6: Verify on-chain bytecode was checked for all 4 contracts
  assert(mockDoc.getElementById('mm-status-CaseRegistry').innerHTML.includes('Deployed'));
  assert(mockDoc.getElementById('mm-status-ValidationQuorum').innerHTML.includes('Deployed'));
  assert(mockDoc.getElementById('mm-status-PostureLedger').innerHTML.includes('Deployed'));
  assert(mockDoc.getElementById('mm-status-Roles').innerHTML.includes('Deployed'));
  console.log('✓ On-chain bytecode inspection verified for CaseRegistry, ValidationQuorum, PostureLedger, and Roles');

  // Test 7: Account change event
  await mockEth.emit('accountsChanged', ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8']);
  assert(mockDoc.getElementById('mm-address-display').innerHTML.includes('0x70997970C51812dc3A010C7d01b50e0d17dc79C8'));

  // Account disconnect (empty accounts)
  await mockEth.emit('accountsChanged', []);
  assert.strictEqual(mockDoc.getElementById('mm-status-badge').textContent, 'DISCONNECTED');
  assert.strictEqual(mockDoc.getElementById('mm-address-display').textContent, 'Not connected');
  console.log('✓ accountsChanged event handled correctly (switching & disconnecting)');

  // Test 8: RPC Disconnect event
  await mockEth.emit('disconnect', { message: 'Connection to node lost' });
  assert.strictEqual(mockDoc.getElementById('mm-status-badge').textContent, 'RPC DISCONNECTED');
  assert(mockDoc.getElementById('mm-alert-box').innerHTML.includes('lost connection to RPC'));
  console.log('✓ RPC disconnect event handled cleanly');

  // Test 9: Strict Read-Only Safety Audit
  const unauthorizedCalls = mockEth.callHistory.filter((c) =>
    ['eth_sendTransaction', 'eth_sign', 'personal_sign', 'eth_signTypedData'].includes(c.method)
  );
  assert.strictEqual(unauthorizedCalls.length, 0, 'No write or signing calls must ever be made');
  console.log('✓ Read-Only Safety Audit passed: 0 transaction/signature requests issued');

  console.log('\nAll MetaMask UI state & wrong-network tests passed successfully! 🎉');
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
