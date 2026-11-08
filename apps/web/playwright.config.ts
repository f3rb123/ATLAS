import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./tests',workers:1,use:{baseURL:'http://localhost:3000',launchOptions:{executablePath:'/usr/bin/chromium',args:['--no-sandbox']},headless:true},reporter:[['list'],['json',{outputFile:'../../docs/test-results/playwright.json'}]]});
