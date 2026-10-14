import * as fs from 'fs';
import * as path from 'path';
import { ethers, network } from 'hardhat';

/**
 * Move the EntryPoint deposit from a retired `CofferdamPaymaster` to the one
 * recorded in `deployments/<network>.json`. Every account-layer redeploy
 * leaves the old paymaster holding the deposit and the new one empty, so
 * sponsored ops fail with AA31 until this runs. `withdrawTo` is owner-only
 * (decision 0014): the signer must own the old paymaster.
 *
 *   OLD_PAYMASTER   the retired paymaster (required)
 *   NEW_PAYMASTER   defaults to `CofferdamPaymaster` in deployments/<network>.json
 *   DEPOSIT_ETH     what to deposit into the new one; default = what was withdrawn
 *   DRY_RUN=1       print balances and the plan, send nothing
 */
async function main() {
  const [signer] = await ethers.getSigners();
  const file = path.join(__dirname, '..', 'deployments', `${network.name}.json`);
  const recorded = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  const oldAddr = process.env.OLD_PAYMASTER?.trim();
  const newAddr = process.env.NEW_PAYMASTER?.trim() || recorded.CofferdamPaymaster?.address;
  if (!oldAddr || !ethers.isAddress(oldAddr)) throw new Error('OLD_PAYMASTER (the retired paymaster) is required');
  if (!newAddr || !ethers.isAddress(newAddr)) {
    throw new Error('NEW_PAYMASTER is unset and deployments/<network>.json has no CofferdamPaymaster');
  }
  if (oldAddr.toLowerCase() === newAddr.toLowerCase()) throw new Error('OLD_PAYMASTER and NEW_PAYMASTER are the same');

  const Paymaster = await ethers.getContractFactory('CofferdamPaymaster');
  const oldPm = Paymaster.attach(oldAddr) as any;
  const newPm = Paymaster.attach(newAddr) as any;
  const entryPoint: string = await newPm.ENTRY_POINT();
  if ((await oldPm.ENTRY_POINT()).toLowerCase() !== entryPoint.toLowerCase()) {
    throw new Error('The two paymasters use different EntryPoints');
  }
  const ep = new ethers.Contract(entryPoint, ['function balanceOf(address) view returns (uint256)'], signer);
  const oldDeposit: bigint = await ep.balanceOf(oldAddr);
  const newDeposit: bigint = await ep.balanceOf(newAddr);
  const owner: string = await oldPm.owner();
  console.log(`signer ${signer.address}: ${ethers.formatEther(await ethers.provider.getBalance(signer.address))} ETH`);
  console.log(`old paymaster ${oldAddr}: deposit ${ethers.formatEther(oldDeposit)} ETH, owner ${owner}`);
  console.log(`new paymaster ${newAddr}: deposit ${ethers.formatEther(newDeposit)} ETH`);
  if (owner.toLowerCase() !== signer.address.toLowerCase()) {
    throw new Error('The signer does not own the old paymaster; withdrawTo is owner-only');
  }
  const amount = process.env.DEPOSIT_ETH ? ethers.parseEther(process.env.DEPOSIT_ETH) : oldDeposit;
  console.log(`plan: withdraw ${ethers.formatEther(oldDeposit)} ETH from the old paymaster, deposit ${ethers.formatEther(amount)} ETH into the new one`);
  if (process.env.DRY_RUN === '1') {
    console.log('DRY_RUN=1: nothing sent');
    return;
  }
  if (oldDeposit > 0n) {
    const tx = await oldPm.withdrawTo(signer.address, oldDeposit);
    console.log('withdrawTo', tx.hash);
    await tx.wait();
  }
  if (amount > 0n) {
    // `receive()` forwards to `ENTRY_POINT.depositTo(address(this))`.
    const tx = await signer.sendTransaction({ to: newAddr, value: amount });
    console.log('deposit', tx.hash);
    await tx.wait();
  }
  console.log(`new paymaster ${newAddr}: deposit now ${ethers.formatEther(await ep.balanceOf(newAddr))} ETH`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
