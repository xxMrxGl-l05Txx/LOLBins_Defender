import axios from 'axios';

// Define alert interface
interface LOLBinAlert {
  id: string;
  binary: string;
  command: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  timestamp: string;
  process_id?: number;
  user?: string;
}

class LOLBinsService {
  private static instance: LOLBinsService;
  private alertsEndpoint = 'http://localhost:5000/alerts';
  private pollingInterval: NodeJS.Timeout | null = null;
  private alertListeners: ((alerts: LOLBinAlert[]) => void)[] = [];
  
  private constructor() {
    // Private constructor to enforce singleton pattern
  }
  
  public static getInstance(): LOLBinsService {
    if (!LOLBinsService.instance) {
      LOLBinsService.instance = new LOLBinsService();
    }
    return LOLBinsService.instance;
  }
  
  /**
   * Fetch alerts from the backend API
   */
  public async fetchAlerts(): Promise<LOLBinAlert[]> {
    try {
      const response = await axios.get(this.alertsEndpoint);
      return response.data as LOLBinAlert[];
    } catch (error) {
      console.error('Error fetching LOLBin alerts:', error);
      return [];
    }
  }
  
  /**
   * Start polling for alerts every 10 seconds
   */
  public startPolling(callback: (alerts: LOLBinAlert[]) => void): void {
    // Add the callback to listeners
    this.alertListeners.push(callback);
    
    // If polling is already active, don't start again
    if (this.pollingInterval) {
      return;
    }
    
    // Initial fetch
    this.fetchAlerts().then(alerts => {
      this.notifyListeners(alerts);
    });
    
    // Set up polling interval
    this.pollingInterval = setInterval(async () => {
      const alerts = await this.fetchAlerts();
      this.notifyListeners(alerts);
    }, 10000); // 10 seconds
  }
  
  /**
   * Stop polling for alerts
   */
  public stopPolling(callback?: (alerts: LOLBinAlert[]) => void): void {
    if (callback) {
      // Remove specific callback if provided
      this.alertListeners = this.alertListeners.filter(listener => listener !== callback);
    } else {
      // Clear all listeners
      this.alertListeners = [];
    }
    
    // If no more listeners, stop the polling
    if (this.alertListeners.length === 0 && this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
  }
  
  /**
   * Notify all registered listeners with the fetched alerts
   */
  private notifyListeners(alerts: LOLBinAlert[]): void {
    this.alertListeners.forEach(listener => {
      listener(alerts);
    });
  }
}

export default LOLBinsService;
