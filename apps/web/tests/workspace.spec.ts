import {test,expect} from '@playwright/test';
import fs from 'node:fs';
const boot=JSON.parse(fs.readFileSync('../../.runtime/e2e-bootstrap.json','utf8'));
test('real owner bootstrap, passkey MFA, campaign, provider UI and corpus search',async({page,context})=>{
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 await page.goto('/');await expect(page.getByRole('heading',{name:'Welcome to ATLAS'})).toBeVisible();
 const setup=page.locator('section').filter({has:page.getByRole('heading',{name:'First owner setup'})});
 await setup.getByLabel('One-time bootstrap token').fill(boot.token);await setup.getByLabel('Owner email').fill(boot.email);await setup.getByLabel('Unique passphrase').fill(boot.password);await setup.getByRole('button',{name:'Create owner'}).click();
 await expect(page.getByRole('heading',{name:'Passkeys & step-up'})).toBeVisible();await page.getByRole('button',{name:'Enroll passkey'}).click();
 await expect(page.getByText('1 passkeys enrolled.',{exact:false})).toBeVisible();await page.getByRole('button',{name:'Authenticate / step-up'}).click();
 await expect(page.getByRole('heading',{name:'System readiness'})).toBeVisible();
 await page.getByRole('button',{name:'Campaigns',exact:true}).click();await page.getByLabel('Campaign name').fill('Local fixture campaign');await page.getByLabel('Authorization reference').fill('Synthetic source-only lab');await page.getByLabel('I am authorized').check();await page.getByRole('button',{name:'Create campaign',exact:true}).click();
 await expect(page.getByRole('button',{name:'Local fixture campaign',exact:false})).toBeVisible();
 await page.getByRole('button',{name:'Providers',exact:true}).click();await expect(page.getByRole('heading',{name:'Add custom provider'})).toBeVisible();await expect(page.getByLabel('Base URL including API prefix')).toBeVisible();
 await page.getByRole('button',{name:'Research Memory',exact:true}).click();await page.getByLabel('Boundary, framework, package, CWE or CVE').fill('tenant authorization');await page.getByRole('button',{name:'Search',exact:true}).click();await expect(page.getByRole('status').locator('pre')).toContainText('source_url');
 await page.screenshot({path:'../../docs/test-results/workspace-memory.png',fullPage:true});
 await page.getByRole('button',{name:'Security',exact:true}).click();await expect(page.getByRole('heading',{name:'Sessions and CLI tokens'})).toBeVisible();
 await page.getByRole('button',{name:'Sign out'}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();
});
