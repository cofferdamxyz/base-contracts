import { expect } from 'chai';
import { ethers } from 'hardhat';
import { Contract, Signer, BigNumberish } from 'ethers';

const ENTRYPOINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

/**
 * Pack two uint128 values into a bytes32 (high 128b = first, low 128b = second).
 * In v0.7: accountGasLimits = pack(verificationGasLimit, callGasLimit)
 *          gasFees = pack(maxPriorityFeePerGas, maxFeePerGas)
 */
function pack128(high: BigNumberish, low: BigNumberish): string {
  const hi = BigInt(high) & ((1n << 128n) - 1n);
  const lo = BigInt(low) & ((1n << 128n) - 1n);
  return '0x' + (hi << 128n | lo).toString(16).padStart(64, '0');
}

describe('EntryPoint v0.7 Integration', function () {
  // These tests require a fork of Base (where EntryPoint v0.7 is preinstalled).
  // We detect this by checking if the EntryPoint has code at the preinstalled address.
  // A pure hardhat in-memory network (without fork) won't have the EntryPoint deployed.
  let isFork = false;

  let entryPoint: Contract;
  let deployer: Signer;
  let deployerAddr: string;

  before(async function () {
    const code = await ethers.provider.getCode(ENTRYPOINT_V07);
    isFork = code !== '0x';
    if (!isFork) {
      this.skip();
      return;
    }
    [deployer] = await ethers.getSigners();
    deployerAddr = await deployer.getAddress();
    entryPoint = await ethers.getContractAt('IEntryPoint', ENTRYPOINT_V07);
  });

  it('should have the correct EntryPoint v0.7 address', async function () {
    if (!isFork) this.skip();
    // EntryPoint v0.7 has code at the preinstalled address on Base forks
    const code = await ethers.provider.getCode(ENTRYPOINT_V07);
    expect(code).to.not.equal('0x');
    expect(code.length).to.be.greaterThan(4);
  });

  it('should deposit and query balance via EntryPoint v0.7', async function () {
    if (!isFork) this.skip();
    const depositAmount = ethers.parseEther('0.5');
    const before = await entryPoint.balanceOf(deployerAddr);
    await entryPoint.depositTo(deployerAddr, { value: depositAmount });
    const after = await entryPoint.balanceOf(deployerAddr);
    expect(after - before).to.equal(depositAmount);
  });

  it('should deploy a CofferdamAccount, send a PackedUserOp through EntryPoint v0.7, and execute a call', async function () {
    if (!isFork) this.skip();

    // 1. Deploy authority module (SessionKeyAuthority — LowUntrusted for testing)
    const SessionKeyAuthority = await ethers.getContractFactory('SessionKeyAuthority');
    const sessionAuth = await SessionKeyAuthority.deploy(1);
    await sessionAuth.waitForDeployment();
    const sessionAuthAddr = await sessionAuth.getAddress();

    // 2. Deploy account factory (for address computation reference)
    const Factory = await ethers.getContractFactory('CofferdamAccountFactory4337');
    const factory = await Factory.deploy(ENTRYPOINT_V07);
    await factory.waitForDeployment();

    // 3. Deploy account directly (bypassing factory CREATE2 to avoid
    //    collisions with EIP-7702 delegated EOAs on the Base Sepolia fork)
    const [signer] = await ethers.getSigners();
    const signerAddr = await signer.getAddress();
    const config = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [signerAddr]);
    const Account = await ethers.getContractFactory('CofferdamAccount4337');
    const account = await Account.deploy(ENTRYPOINT_V07, sessionAuthAddr, config);
    await account.waitForDeployment();
    const accountAddr = await account.getAddress();

    // 4. Fund the account with ETH for gas + execution
    const fundTx = await deployer.sendTransaction({
      to: accountAddr,
      value: ethers.parseEther('1.0'),
    });
    await fundTx.wait();

    // 5. Deploy a simple target contract (a counter) to call via UserOp
    const Counter = await ethers.getContractFactory('MockCounter');
    const counter = await Counter.deploy();
    await counter.waitForDeployment();
    const counterAddr = await counter.getAddress();

    // 6. Account is already deployed — use empty initCode
    const initCode = '0x';

    // 7. Build callData: account.execute(counter, 0, counter.increment())
    const incrementData = counter.interface.encodeFunctionData('increment', []);
    const callData = Account.interface.encodeFunctionData('execute', [
      counterAddr,
      0n,
      incrementData,
    ]);

    // 8. Get the nonce for the account from EntryPoint
    const nonce = await entryPoint.getNonce(accountAddr, 0);

    // 9. Get gas price estimates
    const feeData = await ethers.provider.getFeeData();
    const maxFeePerGas = feeData.maxFeePerGas || ethers.parseUnits('1', 'gwei');
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas || ethers.parseUnits('0.5', 'gwei');

    // 10. Build the PackedUserOperation
    const verificationGasLimit = 500000n;
    const callGasLimit = 200000n;
    const preVerificationGas = 100000n;

    const accountGasLimits = pack128(verificationGasLimit, callGasLimit);
    const gasFees = pack128(maxPriorityFeePerGas, maxFeePerGas);

    // 11. Compute userOpHash via the EntryPoint
    const userOp = {
      sender: accountAddr,
      nonce: nonce,
      initCode: initCode,
      callData: callData,
      accountGasLimits: accountGasLimits,
      preVerificationGas: preVerificationGas,
      gasFees: gasFees,
      paymasterAndData: '0x',
      signature: '0x',
    };

    const userOpHash = await entryPoint.getUserOpHash(userOp);

    // 12. Sign the userOpHash with the session key
    // The account expects: abi.encodePacked(uint256 authorityId, bytes userSig)
    // authorityId = 0 (first authority), userSig = EIP-191 signature of userOpHash
    const signingKey = new ethers.SigningKey(
      '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
    );
    // The SessionKeyAuthority computes: keccak256(account, digest) then EIP-191 prefix
    // But validateUserOp receives userOpHash directly from EntryPoint, and passes it to _authenticate
    // which calls module.isValidSignature(account, userOpHash, config, userSig)
    // SessionKeyAuthority binds: keccak256(abi.encode(account, digest)) then hashMessage
    const bound = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(['address', 'bytes32'], [accountAddr, userOpHash])
    );
    const ethHash = ethers.hashMessage(ethers.getBytes(bound));
    const sig = signingKey.sign(ethHash);
    const userSig = ethers.concat([sig.r, sig.s, ethers.toBeArray(sig.v)]);
    const signature = ethers.solidityPacked(['uint256', 'bytes'], [0, userSig]);

    const signedUserOp = { ...userOp, signature };

    // 13. Deposit some ETH to EntryPoint for the account's gas balance
    await (
      await entryPoint.depositTo(accountAddr, {
        value: ethers.parseEther('0.5'),
      })
    ).wait();

    // 14. Send handleOps — execute the UserOp through EntryPoint v0.7
    const beneficiary = deployerAddr;
    const tx = await entryPoint.handleOps([signedUserOp], beneficiary, {
      gasLimit: 5000000n,
    });
    const receipt = await tx.wait();
    expect(receipt!.status).to.equal(1);

    // 15. Verify the counter was incremented
    expect(await counter.value()).to.equal(1n);

    // 16. Verify the account is deployed (has code)
    const accountCode = await ethers.provider.getCode(accountAddr);
    expect(accountCode).to.not.equal('0x');
  });
});
