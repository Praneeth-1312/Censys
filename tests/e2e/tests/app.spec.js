// @ts-check
const { test, expect } = require('@playwright/test');
const path = require('path');

test.describe('Censys Host Summarizer E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the app
    await page.goto('/');
    
    // Wait for the app to load
    await expect(page.locator('h1')).toContainText('Censys Host Summarizer');
  });

  test('should display the main interface', async ({ page }) => {
    // Check main elements are present
    await expect(page.locator('h1')).toContainText('🔍 Censys Host Summarizer');
    await expect(page.locator('text=Upload your dataset and get intelligent host summaries')).toBeVisible();
    
    // Check for upload section
    await expect(page.locator('text=📁 Upload JSON Dataset')).toBeVisible();
    
    // Check for summarizer section
    await expect(page.locator('text=Host Summarization Ready')).toBeVisible();
  });

  test('should toggle status panel', async ({ page }) => {
    // Initially status panel should be hidden
    await expect(page.locator('[data-testid="status-panel"]')).not.toBeVisible();
    
    // Click show status button
    await page.click('text=📊 Show Status');
    
    // Status panel should now be visible
    await expect(page.locator('[data-testid="status-panel"]')).toBeVisible();
    await expect(page.locator('text=📊 Hide Status')).toBeVisible();
    
    // Click hide status button
    await page.click('text=📊 Hide Status');
    
    // Status panel should be hidden again
    await expect(page.locator('[data-testid="status-panel"]')).not.toBeVisible();
  });

  test('should upload a valid JSON file', async ({ page }) => {
    // Create a test file input
    const fileInput = page.locator('input[type="file"]');
    
    // Upload the sample test data
    const testFilePath = path.join(__dirname, '../data/sample_hosts.json');
    await fileInput.setInputFiles(testFilePath);
    
    // Click upload button
    await page.click('text=📤 Upload');
    
    // Wait for success message
    await expect(page.locator('text=✅ Dataset uploaded successfully')).toBeVisible();
    
    // Check that new upload button appears
    await expect(page.locator('text=↻ New Upload')).toBeVisible();
  });

  test('should show error for invalid file', async ({ page }) => {
    // Create a temporary text file
    const fileInput = page.locator('input[type="file"]');
    
    // Try to upload a non-JSON file (this will be handled by the browser's file picker)
    // For this test, we'll simulate the error by checking the validation
    await fileInput.setInputFiles(path.join(__dirname, '../data/invalid.txt'));
    
    // The validation should prevent upload
    await expect(page.locator('text=Please select a valid JSON file')).toBeVisible();
  });

  test('should summarize individual host after upload', async ({ page }) => {
    // First upload the test data
    const fileInput = page.locator('input[type="file"]');
    const testFilePath = path.join(__dirname, '../data/sample_hosts.json');
    await fileInput.setInputFiles(testFilePath);
    await page.click('text=📤 Upload');
    
    // Wait for upload success
    await expect(page.locator('text=✅ Dataset uploaded successfully')).toBeVisible();
    
    // Now test individual host summarization
    const ipInput = page.locator('input[placeholder="Enter host IP address"]');
    await ipInput.fill('192.168.1.100');
    
    // Click summarize button
    await page.click('text=🚀 Summarize');
    
    // Wait for summary to appear
    await expect(page.locator('text=📋 Analysis Summary')).toBeVisible();
    
    // Check that summary content is displayed
    await expect(page.locator('text=192.168.1.100')).toBeVisible();
  });

  test('should show error for non-existent host', async ({ page }) => {
    // First upload the test data
    const fileInput = page.locator('input[type="file"]');
    const testFilePath = path.join(__dirname, '../data/sample_hosts.json');
    await fileInput.setInputFiles(testFilePath);
    await page.click('text=📤 Upload');
    
    // Wait for upload success
    await expect(page.locator('text=✅ Dataset uploaded successfully')).toBeVisible();
    
    // Try to summarize a non-existent host
    const ipInput = page.locator('input[placeholder="Enter host IP address"]');
    await ipInput.fill('999.999.999.999');
    
    // Click summarize button
    await page.click('text=🚀 Summarize');
    
    // Should show error message
    await expect(page.locator('text=Host not found')).toBeVisible();
  });

  test('should summarize all hosts', async ({ page }) => {
    // First upload the test data
    const fileInput = page.locator('input[type="file"]');
    const testFilePath = path.join(__dirname, '../data/sample_hosts.json');
    await fileInput.setInputFiles(testFilePath);
    await page.click('text=📤 Upload');
    
    // Wait for upload success
    await expect(page.locator('text=✅ Dataset uploaded successfully')).toBeVisible();
    
    // Click summarize all button
    await page.click('text=🚀 Summarize All Hosts');
    
    // Wait for batch results
    await expect(page.locator('text=📈 Batch Analysis Results')).toBeVisible();
    
    // Check that summaries are displayed
    await expect(page.locator('text=3 hosts')).toBeVisible();
  });

  test('should handle new upload after previous upload', async ({ page }) => {
    // First upload
    const fileInput = page.locator('input[type="file"]');
    const testFilePath = path.join(__dirname, '../data/sample_hosts.json');
    await fileInput.setInputFiles(testFilePath);
    await page.click('text=📤 Upload');
    
    // Wait for upload success
    await expect(page.locator('text=✅ Dataset uploaded successfully')).toBeVisible();
    
    // Click new upload button
    await page.click('text=↻ New Upload');
    
    // File input should be cleared
    await expect(fileInput).toHaveValue('');
    
    // Upload button should be reset
    await expect(page.locator('text=Select File First')).toBeVisible();
  });

  test('should show loading states during operations', async ({ page }) => {
    // Upload file
    const fileInput = page.locator('input[type="file"]');
    const testFilePath = path.join(__dirname, '../data/sample_hosts.json');
    await fileInput.setInputFiles(testFilePath);
    
    // Click upload and check loading state
    await page.click('text=📤 Upload');
    await expect(page.locator('text=⏳ Uploading...')).toBeVisible();
    
    // Wait for upload to complete
    await expect(page.locator('text=✅ Dataset uploaded successfully')).toBeVisible();
    
    // Test summarization loading state
    const ipInput = page.locator('input[placeholder="Enter host IP address"]');
    await ipInput.fill('192.168.1.100');
    await page.click('text=🚀 Summarize');
    
    // Should show analyzing state
    await expect(page.locator('text=⏳ Analyzing...')).toBeVisible();
  });

  test('should be responsive on mobile viewport', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Check that main elements are still visible
    await expect(page.locator('h1')).toBeVisible();
    await expect(page.locator('text=📁 Upload JSON Dataset')).toBeVisible();
    
    // Check that status toggle button is accessible
    await expect(page.locator('text=📊 Show Status')).toBeVisible();
  });
});
