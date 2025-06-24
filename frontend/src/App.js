import React, { useState, useEffect } from 'react';
import './App.css';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [scanPath, setScanPath] = useState('/app');
  const [currentScan, setCurrentScan] = useState(null);
  const [scanResults, setScanResults] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [quarantineItems, setQuarantineItems] = useState([]);
  const [dashboardStats, setDashboardStats] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Fetch dashboard stats
  const fetchDashboardStats = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/stats`);
      const data = await response.json();
      setDashboardStats(data);
    } catch (err) {
      console.error('Failed to fetch dashboard stats:', err);
    }
  };

  // Fetch scan history
  const fetchScanHistory = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/scans/history`);
      const data = await response.json();
      setScanHistory(data.scans || []);
    } catch (err) {
      console.error('Failed to fetch scan history:', err);
    }
  };

  // Fetch quarantine items
  const fetchQuarantineItems = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/quarantine`);
      const data = await response.json();
      setQuarantineItems(data.quarantine_items || []);
    } catch (err) {
      console.error('Failed to fetch quarantine items:', err);
    }
  };

  // Start scan
  const startScan = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/scan/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          directory_path: scanPath,
          scan_type: 'quick'
        })
      });

      const data = await response.json();
      
      if (response.ok) {
        setCurrentScan({ scan_id: data.scan_id, status: 'in_progress' });
        // Start polling for status
        pollScanStatus(data.scan_id);
      } else {
        setError(data.detail || 'Failed to start scan');
      }
    } catch (err) {
      setError('Failed to start scan: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Poll scan status
  const pollScanStatus = async (scanId) => {
    const poll = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/scan/status/${scanId}`);
        const data = await response.json();
        
        setCurrentScan(data);
        
        if (data.status === 'completed') {
          // Fetch results
          const resultsResponse = await fetch(`${API_BASE_URL}/api/scan/results/${scanId}`);
          const resultsData = await resultsResponse.json();
          setScanResults(resultsData.results || []);
          
          // Refresh other data
          fetchDashboardStats();
          fetchScanHistory();
          fetchQuarantineItems();
          
          return; // Stop polling
        }
        
        // Continue polling if not completed
        setTimeout(poll, 3000);
      } catch (err) {
        console.error('Failed to fetch scan status:', err);
      }
    };
    
    poll();
  };

  // Restore quarantine item
  const restoreQuarantineItem = async (quarantineId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/quarantine/restore/${quarantineId}`, {
        method: 'POST'
      });
      
      if (response.ok) {
        fetchQuarantineItems();
        fetchDashboardStats();
      } else {
        const data = await response.json();
        alert(data.detail || 'Failed to restore file');
      }
    } catch (err) {
      alert('Failed to restore file: ' + err.message);
    }
  };

  // Delete quarantine item
  const deleteQuarantineItem = async (quarantineId) => {
    if (!window.confirm('Are you sure you want to permanently delete this file?')) {
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/quarantine/delete/${quarantineId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        fetchQuarantineItems();
        fetchDashboardStats();
      } else {
        const data = await response.json();
        alert(data.detail || 'Failed to delete file');
      }
    } catch (err) {
      alert('Failed to delete file: ' + err.message);
    }
  };

  // Load initial data
  useEffect(() => {
    fetchDashboardStats();
    fetchScanHistory();
    fetchQuarantineItems();
  }, []);

  const getThreatColor = (threatLevel) => {
    switch (threatLevel) {
      case 'clean': return 'text-green-600';
      case 'low': return 'text-yellow-600';
      case 'medium': return 'text-orange-600';
      case 'high': return 'text-red-600';
      case 'critical': return 'text-red-800';
      default: return 'text-gray-600';
    }
  };

  const getThreatBadgeColor = (threatLevel) => {
    switch (threatLevel) {
      case 'clean': return 'bg-green-100 text-green-800';
      case 'low': return 'bg-yellow-100 text-yellow-800';
      case 'medium': return 'bg-orange-100 text-orange-800';
      case 'high': return 'bg-red-100 text-red-800';
      case 'critical': return 'bg-red-200 text-red-900';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
              </div>
              <div className="ml-3">
                <h1 className="text-2xl font-bold text-gray-900">SecureGuard Antivirus</h1>
                <p className="text-sm text-gray-500">Advanced threat detection & protection</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-500">
                Last updated: {dashboardStats.last_updated ? new Date(dashboardStats.last_updated).toLocaleTimeString() : 'Never'}
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {[
              { id: 'dashboard', name: 'Dashboard', icon: '📊' },
              { id: 'scanner', name: 'Scanner', icon: '🔍' },
              { id: 'quarantine', name: 'Quarantine', icon: '🔒' },
              { id: 'history', name: 'History', icon: '📋' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <span className="mr-2">{tab.icon}</span>
                {tab.name}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                      <span className="text-blue-600 text-lg">🔍</span>
                    </div>
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-gray-500">Total Scans</p>
                    <p className="text-2xl font-semibold text-gray-900">{dashboardStats.total_scans || 0}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
                      <span className="text-green-600 text-lg">📁</span>
                    </div>
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-gray-500">Files Scanned</p>
                    <p className="text-2xl font-semibold text-gray-900">{dashboardStats.total_files_scanned || 0}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-red-100 rounded-lg flex items-center justify-center">
                      <span className="text-red-600 text-lg">⚠️</span>
                    </div>
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-gray-500">Threats Found</p>
                    <p className="text-2xl font-semibold text-gray-900">{dashboardStats.total_threats_found || 0}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-yellow-100 rounded-lg flex items-center justify-center">
                      <span className="text-yellow-600 text-lg">🔒</span>
                    </div>
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-gray-500">Quarantined</p>
                    <p className="text-2xl font-semibold text-gray-900">{dashboardStats.quarantine_count || 0}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Activity */}
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Recent Scans</h3>
              </div>
              <div className="divide-y divide-gray-200">
                {dashboardStats.recent_scans && dashboardStats.recent_scans.length > 0 ? (
                  dashboardStats.recent_scans.map((scan) => (
                    <div key={scan.scan_id} className="px-6 py-4 flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-900">{scan.directory_path}</p>
                        <p className="text-sm text-gray-500">
                          {new Date(scan.started_date).toLocaleDateString()} at {new Date(scan.started_date).toLocaleTimeString()}
                        </p>
                      </div>
                      <div>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          scan.scan_completed ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                        }`}>
                          {scan.scan_completed ? 'Completed' : 'In Progress'}
                        </span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="px-6 py-4 text-center text-gray-500">
                    No recent scans
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Scanner Tab */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            {/* Scan Configuration */}
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Directory Scanner</h3>
                <p className="text-sm text-gray-500">Scan directories for viruses and malware</p>
              </div>
              <div className="px-6 py-4 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Directory Path</label>
                  <input
                    type="text"
                    value={scanPath}
                    onChange={(e) => setScanPath(e.target.value)}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="/path/to/scan"
                  />
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500">
                      This will scan all supported files in the specified directory and subdirectories.
                    </p>
                  </div>
                  <button
                    onClick={startScan}
                    disabled={loading || (currentScan && currentScan.status === 'in_progress')}
                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400"
                  >
                    {loading ? 'Starting...' : 'Start Scan'}
                  </button>
                </div>
                
                {error && (
                  <div className="bg-red-50 border border-red-200 rounded-md p-4">
                    <p className="text-sm text-red-600">{error}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Current Scan Status */}
            {currentScan && (
              <div className="bg-white rounded-lg shadow">
                <div className="px-6 py-4 border-b border-gray-200">
                  <h3 className="text-lg font-medium text-gray-900">Current Scan</h3>
                </div>
                <div className="px-6 py-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div>
                      <p className="text-sm font-medium text-gray-500">Status</p>
                      <p className="text-lg font-semibold text-gray-900">{currentScan.status}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-500">Files Scanned</p>
                      <p className="text-lg font-semibold text-gray-900">{currentScan.total_files || 0}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-500">Threats Found</p>
                      <p className="text-lg font-semibold text-red-600">{currentScan.infected_files || 0}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-500">Clean Files</p>
                      <p className="text-lg font-semibold text-green-600">{currentScan.clean_files || 0}</p>
                    </div>
                  </div>
                  
                  {currentScan.status === 'in_progress' && (
                    <div className="mt-4">
                      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                        <div className="flex items-center">
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
                          <p className="ml-3 text-sm text-blue-600">Scanning in progress... This may take several minutes.</p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Scan Results */}
            {scanResults.length > 0 && (
              <div className="bg-white rounded-lg shadow">
                <div className="px-6 py-4 border-b border-gray-200">
                  <h3 className="text-lg font-medium text-gray-900">Scan Results</h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">File</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Level</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Detections</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threats</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {scanResults.map((result, index) => (
                        <tr key={index}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div>
                              <p className="text-sm font-medium text-gray-900">{result.file_name}</p>
                              <p className="text-sm text-gray-500">{result.file_path}</p>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              result.scan_status === 'clean' ? 'bg-green-100 text-green-800' : 
                              result.scan_status === 'infected' ? 'bg-red-100 text-red-800' : 
                              'bg-gray-100 text-gray-800'
                            }`}>
                              {result.scan_status}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getThreatBadgeColor(result.threat_level)}`}>
                              {result.threat_level}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {result.detection_count}/{result.total_engines}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {result.virus_names.length > 0 ? result.virus_names.join(', ') : 'None'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Quarantine Tab */}
        {activeTab === 'quarantine' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Quarantined Files</h3>
                <p className="text-sm text-gray-500">Files that have been isolated due to detected threats</p>
              </div>
              
              {quarantineItems.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">File</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat Level</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threats</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Quarantined</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {quarantineItems.map((item) => (
                        <tr key={item.quarantine_id}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div>
                              <p className="text-sm font-medium text-gray-900">{item.file_name}</p>
                              <p className="text-sm text-gray-500">{item.original_path}</p>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getThreatBadgeColor(item.threat_level)}`}>
                              {item.threat_level}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {item.virus_names.join(', ')}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(item.quarantined_date).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                            {!item.restored && (
                              <>
                                <button
                                  onClick={() => restoreQuarantineItem(item.quarantine_id)}
                                  className="text-blue-600 hover:text-blue-900"
                                >
                                  Restore
                                </button>
                                <button
                                  onClick={() => deleteQuarantineItem(item.quarantine_id)}
                                  className="text-red-600 hover:text-red-900"
                                >
                                  Delete
                                </button>
                              </>
                            )}
                            {item.restored && (
                              <span className="text-green-600">Restored</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="px-6 py-12 text-center">
                  <div className="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center">
                    <span className="text-2xl text-gray-400">🔒</span>
                  </div>
                  <h3 className="mt-4 text-lg font-medium text-gray-900">No quarantined files</h3>
                  <p className="mt-2 text-sm text-gray-500">Files detected as threats will appear here.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Scan History</h3>
                <p className="text-sm text-gray-500">View all previous scans and their results</p>
              </div>
              
              {scanHistory.length > 0 ? (
                <div className="divide-y divide-gray-200">
                  {scanHistory.map((scan) => (
                    <div key={scan.scan_id} className="px-6 py-4">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-4">
                            <div>
                              <p className="text-sm font-medium text-gray-900">{scan.directory_path}</p>
                              <p className="text-sm text-gray-500">
                                Started: {new Date(scan.started_date).toLocaleString()}
                                {scan.completed_date && (
                                  <span> • Completed: {new Date(scan.completed_date).toLocaleString()}</span>
                                )}
                              </p>
                            </div>
                          </div>
                          <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500">
                            <span>Files: {scan.total_files || 0}</span>
                            <span>Threats: <span className="text-red-600">{scan.infected_files || 0}</span></span>
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              scan.scan_completed ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                            }`}>
                              {scan.scan_completed ? 'Completed' : 'In Progress'}
                            </span>
                          </div>
                        </div>
                        <div className="flex-shrink-0">
                          <button
                            onClick={() => {
                              setCurrentScan(scan);
                              setActiveTab('scanner');
                              // Fetch results for this scan
                              fetch(`${API_BASE_URL}/api/scan/results/${scan.scan_id}`)
                                .then(res => res.json())
                                .then(data => setScanResults(data.results || []))
                                .catch(err => console.error('Failed to fetch scan results:', err));
                            }}
                            className="text-blue-600 hover:text-blue-900 text-sm font-medium"
                          >
                            View Details
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="px-6 py-12 text-center">
                  <div className="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center">
                    <span className="text-2xl text-gray-400">📋</span>
                  </div>
                  <h3 className="mt-4 text-lg font-medium text-gray-900">No scan history</h3>
                  <p className="mt-2 text-sm text-gray-500">Your scan history will appear here after running scans.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;