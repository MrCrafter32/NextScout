'use client';

import { useState, FC, ReactNode, FormEvent } from 'react';

// --- Type Definitions ---
interface Vulnerability {
  type: string;
  page: string;
  formAction: string;
  vulnerableParams: string[];
}

interface FormInput {
    type: string;
    name?: string;
}

interface DiscoveredForm {
    page: string;
    action: string;
    method: string;
    inputs: FormInput[];
}

interface ScanResults {
    message: string;
    vulnerabilities: Vulnerability[];
    discoveredLinks: string[];
    discoveredForms: DiscoveredForm[];
}


// --- UI Components ---
const ChevronDown: FC = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m6 9 6 6 6-6"/></svg>
);
const AlertTriangle: FC = () => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-red-400"><path d="m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
);

interface CollapsibleProps {
    title: string;
    count: number;
    children: ReactNode;
}

const CollapsibleSection: FC<CollapsibleProps> = ({ title, count, children }) => {
    const [isOpen, setIsOpen] = useState(false);
    return (
        <div className="bg-gray-800 border border-gray-700 rounded-lg">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="w-full flex justify-between items-center p-4 text-left font-semibold"
            >
                <span>{title} ({count})</span>
                <span className={`transform transition-transform ${isOpen ? 'rotate-180' : ''}`}><ChevronDown /></span>
            </button>
            {isOpen && <div className="p-4 border-t border-gray-700">{children}</div>}
        </div>
    );
};


export default function Home() {
  const [url, setUrl] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string>('');

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!url || !url.startsWith('http')) {
      setError('Please enter a valid URL (e.g., http://example.com)');
      return;
    }
    setError('');
    setIsLoading(true);
    setResults(null); 

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
      }

      const data: ScanResults = await response.json();
      setResults(data);

    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleNewScan = () => {
    setUrl('');
    setResults(null);
    setError('');
  }

  return (
    <main className="flex min-h-screen flex-col items-center p-4 sm:p-8 bg-gray-900 text-white font-sans">
      <div className="w-full max-w-6xl">
        <div className="text-center mb-10">
            <h1 className="text-5xl font-bold mb-2 text-cyan-400">Next Scout</h1>
            <p className="text-lg text-gray-400">
                A simple web vulnerability scanner.
            </p>
        </div>

        {/* Initial View & Loading State */}
        {!results && (
             <div className="w-full max-w-3xl mx-auto">
                <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-4 w-full mb-8">
                <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="e.g., http://testphp.vulnweb.com"
                    className="flex-grow p-4 rounded-md bg-gray-800 border border-gray-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 text-white transition"
                    disabled={isLoading}
                />
                <button
                    type="submit"
                    className="bg-cyan-500 hover:bg-cyan-600 text-gray-900 font-bold py-4 px-6 rounded-md transition-colors duration-300 disabled:bg-gray-600 disabled:cursor-not-allowed"
                    disabled={isLoading}
                >
                    {isLoading ? 'Scanning...' : 'Scan'}
                </button>
                </form>

                {error && <p className="text-center my-4 text-red-400">{error}</p>}

                {isLoading && (
                <div className="text-center my-8">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto"></div>
                    <p className="mt-4 text-gray-400">Analyzing target... this may take a moment.</p>
                </div>
                )}
            </div>
        )}

        {/* Results View */}
        {results && (
          <div className="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Left Column */}
            <div className="space-y-6">
                <div className="p-6 bg-gray-800 rounded-lg border border-gray-700">
                    <h2 className="text-2xl font-bold mb-4 text-cyan-400">Scan Summary</h2>
                    <p className="text-gray-300">{results.message}</p>
                     <button 
                        onClick={handleNewScan}
                        className="mt-4 bg-cyan-600 hover:bg-cyan-700 text-white font-bold py-2 px-4 rounded-md transition-colors duration-300"
                    >
                        Start New Scan
                    </button>
                </div>
            
                {results.vulnerabilities && results.vulnerabilities.length > 0 && (
                    <div className="p-6 bg-red-900/20 border border-red-400/50 rounded-lg">
                        <h2 className="text-2xl font-bold mb-4 text-red-400 flex items-center gap-3">
                            <AlertTriangle /> Vulnerabilities Found
                        </h2>
                        <div className="space-y-4">
                            {results.vulnerabilities.map((vuln, index) => (
                                <div key={index} className="bg-gray-800 p-4 rounded-md">
                                    <p><strong className="text-cyan-400">Type:</strong> {vuln.type}</p>
                                    <p><strong className="text-cyan-400">Location:</strong> {vuln.page}</p>
                                    <p><strong className="text-cyan-400">Vulnerable Parameters:</strong> {vuln.vulnerableParams.join(', ')}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            {/* Right Column */}
            <div className="space-y-6">
                <CollapsibleSection title="Discovered Links" count={results.discoveredLinks?.length || 0}>
                    <div className="max-h-60 overflow-y-auto text-sm space-y-2 pr-2">
                        {results.discoveredLinks.map((link, i) => <p key={i} className="truncate text-gray-400">{link}</p>)}
                    </div>
                </CollapsibleSection>

                <CollapsibleSection title="Discovered Forms" count={results.discoveredForms?.length || 0}>
                    <div className="max-h-80 overflow-y-auto text-sm space-y-4 pr-2">
                        {results.discoveredForms.map((form, i) => (
                            <div key={i} className="bg-gray-900 p-3 rounded">
                                <p><strong className="text-cyan-500">Page:</strong> {form.page}</p>
                                <p><strong className="text-cyan-500">Action:</strong> {form.action}</p>
                                <p><strong className="text-cyan-500">Method:</strong> {form.method}</p>
                                <p><strong className="text-cyan-500">Inputs:</strong> {form.inputs.map(inp => inp.name || '[unnamed]').join(', ')}</p>
                            </div>
                        ))}
                    </div>
                </CollapsibleSection>
            </div>
          </div>
        )}
        
        <footer className="text-center mt-16 text-gray-500 text-sm">
            <p>Developed by Swapneel Ghosh & Jagadeesh Chandra Duggirala.</p>
            <p className="mt-2 font-mono text-xs">Disclaimer: Use only for authorized and educational purposes.</p>
        </footer>
      </div>
    </main>
  );
}

