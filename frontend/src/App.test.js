import { render, screen } from '@testing-library/react';
import App from './App';

// Mock axios to prevent API calls during testing
jest.mock('axios', () => ({
  get: jest.fn(() => Promise.reject(new Error('Network Error'))),
  post: jest.fn(() => Promise.reject(new Error('Network Error'))),
}));

test('renders Censys Host Summarizer title', () => {
  render(<App />);
  const titleElement = screen.getByText(/Censys Host Summarizer/i);
  expect(titleElement).toBeInTheDocument();
});

test('renders upload section', () => {
  render(<App />);
  const uploadTitle = screen.getByText(/Upload JSON Dataset/i);
  expect(uploadTitle).toBeInTheDocument();
});

test('renders summarizer section', () => {
  render(<App />);
  const summarizerTitle = screen.getByText(/Host Summarization Ready/i);
  expect(summarizerTitle).toBeInTheDocument();
});
