import { expect } from 'chai';
import { ethers } from 'hardhat';

/**
 * CofferdamCompanyRegistry and CofferdamCorporateRegistry access control
 * (2026-10-15): the registrar (owner) registers and pauses; the company's own
 * wallet, as the company registry records it, signs root updates and witness
 * changes (decision 0026); nobody else writes anything.
 */

const domainHash = (domain: string) => ethers.id(domain);
const anchorOf = (domain: string) => ethers.keccak256(ethers.concat([ethers.toUtf8Bytes('cofferdam-company-v1'), ethers.toUtf8Bytes(domain)]));

async function deployFixture() {
  const [registrar, companySafe, otherSafe, witness, stranger] = await ethers.getSigners();
  const Company = await ethers.getContractFactory('CofferdamCompanyRegistry');
  const company = (await Company.deploy(registrar.address)) as any;
  await company.waitForDeployment();
  const Corporate = await ethers.getContractFactory('CofferdamCorporateRegistry');
  const corporate = (await Corporate.deploy(await company.getAddress(), registrar.address)) as any;
  await corporate.waitForDeployment();
  const proof = ethers.id('cofferdam-site-verification=acme');
  return { registrar, companySafe, otherSafe, witness, stranger, company, corporate, proof };
}

async function registered() {
  const ctx = await deployFixture();
  await (await ctx.company.registerCompany(domainHash('acme.com'), anchorOf('acme.com'), ctx.companySafe.address, ctx.proof)).wait();
  return { ...ctx, anchor: anchorOf('acme.com'), domain: domainHash('acme.com') };
}

describe('CofferdamCompanyRegistry', () => {
  it('lets only the registrar register, with a wallet, once per domain and once per anchor', async () => {
    const ctx = await deployFixture();
    const d = domainHash('acme.com');
    const a = anchorOf('acme.com');
    await expect(ctx.company.connect(ctx.stranger).registerCompany(d, a, ctx.companySafe.address, ctx.proof))
      .to.be.revertedWithCustomError(ctx.company, 'NotOwner');
    await expect(ctx.company.registerCompany(d, a, ethers.ZeroAddress, ctx.proof)).to.be.revertedWith('Invalid companyWallet');
    await expect(ctx.company.registerCompany(d, ethers.ZeroHash, ctx.companySafe.address, ctx.proof)).to.be.revertedWith('Invalid companyAnchor');

    await expect(ctx.company.registerCompany(d, a, ctx.companySafe.address, ctx.proof))
      .to.emit(ctx.company, 'CompanyRegistered')
      .withArgs(a, d, ctx.companySafe.address, ctx.proof, (t: bigint) => t > 0n);
    expect(await ctx.company.companyWalletOf(a)).to.equal(ctx.companySafe.address);
    expect(await ctx.company.getCompanyWallet(d)).to.equal(ctx.companySafe.address);
    expect(await ctx.company.domainCount()).to.equal(1n);

    // The duplicate guards fire now that a wallet is recorded.
    await expect(ctx.company.registerCompany(d, anchorOf('acme.org'), ctx.otherSafe.address, ctx.proof)).to.be.revertedWith('Already registered');
    await expect(ctx.company.registerCompany(domainHash('acme.org'), a, ctx.otherSafe.address, ctx.proof)).to.be.revertedWith('Anchor already registered');
    expect(await ctx.company.companyWalletOf(anchorOf('nobody.com'))).to.equal(ethers.ZeroAddress);
  });

  it('pauses and unpauses registered companies on the registrar\'s call only', async () => {
    const ctx = await registered();
    await expect(ctx.company.connect(ctx.companySafe).pauseCompany(ctx.domain)).to.be.revertedWithCustomError(ctx.company, 'NotOwner');
    await expect(ctx.company.pauseCompany(domainHash('nobody.com'))).to.be.revertedWith('Not registered');
    await (await ctx.company.pauseCompany(ctx.domain)).wait();
    expect(await ctx.company.isCompanyPaused(ctx.domain)).to.be.true;
    await (await ctx.company.unpauseCompany(ctx.domain)).wait();
    expect(await ctx.company.isCompanyPaused(ctx.domain)).to.be.false;
  });

  it('transfers ownership in two steps', async () => {
    const ctx = await deployFixture();
    await (await ctx.company.transferOwnership(ctx.otherSafe.address)).wait();
    expect(await ctx.company.owner()).to.equal(ctx.registrar.address);
    await expect(ctx.company.connect(ctx.stranger).acceptOwnership()).to.be.revertedWithCustomError(ctx.company, 'NotPendingOwner');
    await (await ctx.company.connect(ctx.otherSafe).acceptOwnership()).wait();
    expect(await ctx.company.owner()).to.equal(ctx.otherSafe.address);
    await expect(ctx.company.registerCompany(domainHash('x.com'), anchorOf('x.com'), ctx.companySafe.address, ctx.proof))
      .to.be.revertedWithCustomError(ctx.company, 'NotOwner');
  });
});

describe('CofferdamCorporateRegistry', () => {
  it('takes root updates from the company\'s registered wallet only, and counts generations', async () => {
    const ctx = await registered();
    const root = ethers.id('org-root-1');
    await expect(ctx.corporate.connect(ctx.stranger).updateOrgRoot(ctx.anchor, root)).to.be.revertedWithCustomError(ctx.corporate, 'NotCompany');
    // The registrar holds no execution rights over a company's entries (decision 0026).
    await expect(ctx.corporate.connect(ctx.registrar).updateOrgRoot(ctx.anchor, root)).to.be.revertedWithCustomError(ctx.corporate, 'NotCompany');
    // An unregistered anchor has no wallet, so nobody can write it.
    await expect(ctx.corporate.connect(ctx.companySafe).updateOrgRoot(anchorOf('nobody.com'), root)).to.be.revertedWithCustomError(ctx.corporate, 'NotCompany');

    await expect(ctx.corporate.connect(ctx.companySafe).updateOrgRoot(ctx.anchor, root))
      .to.emit(ctx.corporate, 'OrgRootUpdated')
      .withArgs(ctx.anchor, root, 1, (t: bigint) => t > 0n);
    await (await ctx.corporate.connect(ctx.companySafe).updateOrgRoot(ctx.anchor, ethers.id('org-root-2'))).wait();
    const [r, generation] = await ctx.corporate.getOrgRoot(ctx.anchor);
    expect(r).to.equal(ethers.id('org-root-2'));
    expect(generation).to.equal(2n);
  });

  it('lets the registrar pause, which blocks root updates and nothing else', async () => {
    const ctx = await registered();
    await expect(ctx.corporate.connect(ctx.companySafe).pauseCompany(ctx.anchor)).to.be.revertedWithCustomError(ctx.corporate, 'NotOwner');
    await (await ctx.corporate.pauseCompany(ctx.anchor)).wait();
    await expect(ctx.corporate.connect(ctx.companySafe).updateOrgRoot(ctx.anchor, ethers.id('r'))).to.be.revertedWith('Company paused');
    // Witness delegation still works for the company while paused.
    await (await ctx.corporate.connect(ctx.companySafe).delegateWitness(ctx.anchor, ctx.witness.address)).wait();
    expect(await ctx.corporate.isWitnessDelegated(ctx.anchor, ctx.witness.address)).to.be.true;
    await (await ctx.corporate.unpauseCompany(ctx.anchor)).wait();
    await (await ctx.corporate.connect(ctx.companySafe).updateOrgRoot(ctx.anchor, ethers.id('r'))).wait();
  });

  it('lets only the company delegate and revoke witnesses', async () => {
    const ctx = await registered();
    await expect(ctx.corporate.connect(ctx.registrar).delegateWitness(ctx.anchor, ctx.witness.address)).to.be.revertedWithCustomError(ctx.corporate, 'NotCompany');
    await expect(ctx.corporate.connect(ctx.companySafe).delegateWitness(ctx.anchor, ethers.ZeroAddress)).to.be.revertedWith('Invalid witness');
    await (await ctx.corporate.connect(ctx.companySafe).delegateWitness(ctx.anchor, ctx.witness.address)).wait();
    await expect(ctx.corporate.connect(ctx.witness).revokeWitness(ctx.anchor, ctx.witness.address)).to.be.revertedWithCustomError(ctx.corporate, 'NotCompany');
    await (await ctx.corporate.connect(ctx.companySafe).revokeWitness(ctx.anchor, ctx.witness.address)).wait();
    expect(await ctx.corporate.isWitnessDelegated(ctx.anchor, ctx.witness.address)).to.be.false;
  });
});
