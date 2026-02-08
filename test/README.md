# Gator Safe App — Local Testing

## Prerequisites

- **Foundry** installed at `$HOME/.foundry/bin/` (anvil + forge)
- **Node.js** v18+
- **DeleGator Safe Module** repo at `~/projects/delegator-safe-module/`

## Quick Start

```bash
# Terminal 1: Start Anvil (Base Sepolia fork)
npm run test:anvil

# Terminal 2: Run setup + tests
npm run test:all
```

## Scripts

| Script | Description |
|--------|-------------|
| `npm run test:anvil` | Start Anvil with Base Sepolia fork on port 8545 |
| `npm run test:setup` | Deploy Safe (2/3 multisig) + DeleGatorModuleFactory + Module |
| `npm run test:flow` | Run full delegation flow tests |
| `npm run test:all` | Run setup + flow tests sequentially |

## What `test:setup` Does

1. Creates a **2/3 Safe multisig** with Anvil's first 3 default accounts
2. Funds the Safe with **10 ETH**
3. Deploys **DeleGatorModuleFactory** via forge
4. Deploys a **DeleGatorModule** for the Safe
5. **Enables the module** on the Safe (2/3 multisig tx)
6. Saves deployment info to `test/deployment.json`

## What `test:flow` Does

1. Verifies Safe owners, threshold, module enabled
2. Creates a **NativeTokenPeriodTransferEnforcer** delegation (1 ETH/day)
3. Signs delegation with **2/3 owners** via EIP-712
4. Validates the delegation struct and hash
5. Exports/imports delegation as JSON

## Test Accounts (Anvil defaults)

| # | Address | Role |
|---|---------|------|
| 0 | `0xf39F...2266` | Safe Owner 1 |
| 1 | `0x7099...79C8` | Safe Owner 2 |
| 2 | `0x3C44...93BC` | Safe Owner 3 |
| 9 | `0xa0Ee...9720` | Delegate (recipient of permissions) |

## Contract Addresses (Forked from Base Sepolia)

- **DelegationManager:** `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3`
- **NativeTokenPeriodTransferEnforcer:** `0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9`
- **ERC20PeriodTransferEnforcer:** `0x474e3Ae7E169e940607cC624Da8A15Eb120139aB`

Factory and module addresses are generated during setup and saved to `deployment.json`.
