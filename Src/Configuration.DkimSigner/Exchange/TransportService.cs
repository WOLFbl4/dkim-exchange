using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Threading;

namespace Configuration.DkimSigner.Exchange
{
	public class TransportService : IDisposable
	{
		public event EventHandler StatusChanged;

		private sealed class QueuedAction
		{
			public TransportServiceAction Action { get; private set; }
			public Action<string> ErrorCallback { get; private set; }

			public QueuedAction(TransportServiceAction action, Action<string> errorCallback)
			{
				Action = action;
				ErrorCallback = errorCallback;
			}
		}

		private static readonly TimeSpan ServiceOperationTimeout = TimeSpan.FromMinutes(2);
		private static readonly TimeSpan WorkerShutdownTimeout = TimeSpan.FromMinutes(5);

		private Thread thread;
		private Timer transportServiceStatus;

		private readonly Queue<QueuedAction> actions;
		private readonly object serviceMutex = new object();
		private ServiceController service;
		private volatile string status;
		private bool workerRunning;
		private bool disposed;

		/// <summary>
		/// Constructor
		/// </summary>
		public TransportService()
		{
			if (!IsTransportServiceInstalled())
			{
				throw new ExchangeServerException("No service 'MSExchangeTransport' available.");
			}

			actions = new Queue<QueuedAction>();
			service = new ServiceController("MSExchangeTransport");
			transportServiceStatus = new Timer(CheckExchangeTransportServiceStatus, null, 0, 1000);
		}

		/// <summary>
		/// Check if Microsoft Exchange Transport service is installed
		/// </summary>
		/// <returns>bool</returns>
		private bool IsTransportServiceInstalled()
		{
			return (ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == "MSExchangeTransport") != null);
		}

		/// <summary>
		/// Get Microsoft Exchange Transport service status
		/// </summary>
		/// <returns>ServiceControllerStatus</returns>
		private ServiceControllerStatus GetTransportServiceStatus()
		{
			lock (serviceMutex)
			{
				service.Refresh();
				return service.Status;
			}
		}

		/// <summary>
		/// Check the Microsoft Exchange Transport service status
		/// </summary>
		/// <param name="state"></param>
		private void CheckExchangeTransportServiceStatus(object state)
		{
			try
			{
				string s = GetTransportServiceStatus().ToString();

				if (status != s)
				{
					status = s;
					EventHandler handler = StatusChanged;
					if (handler != null)
					{
						handler(this, EventArgs.Empty);
					}
				}
			}
			catch (Exception)
			{
				Timer timer = transportServiceStatus;
				if (timer != null)
				{
					try
					{
						timer.Change(Timeout.Infinite, Timeout.Infinite);
					}
					catch (ObjectDisposedException) { }
				}
			}
		}

		/// <summary>
		/// Execute a action (start, stop, restart) on Microsoft Exchange Transport service
		/// </summary>
		private void ExecuteAction()
		{
			while (true)
			{
				QueuedAction queuedAction;

				lock (actions)
				{
					if (actions.Count == 0)
					{
						workerRunning = false;
						return;
					}

					queuedAction = actions.Dequeue();
				}

				try
				{
					if (queuedAction.Action == TransportServiceAction.Start)
					{
						StartTransportService();
					}
					else
					{
						StopTransportService();
					}
				}
				catch (Exception e)
				{
					string operation = queuedAction.Action == TransportServiceAction.Start ? "start" : "stop";
					string message = "Couldn't " + operation + " 'MSExchangeTransport' service :\n" + e.Message + "\nMake sure you are running the program as an administrator.";
					if (queuedAction.ErrorCallback != null)
					{
						try
						{
							queuedAction.ErrorCallback(message);
						}
						catch (Exception callbackError)
						{
							System.Diagnostics.Trace.TraceError(callbackError.ToString());
						}
					}
				}
			}
		}

		private void StartTransportService()
		{
			lock (serviceMutex)
			{
				StartTransportServiceLocked();
			}
		}

		private void StartTransportServiceLocked()
		{
			ServiceControllerStatus currentStatus = GetTransportServiceStatus();
			if (currentStatus == ServiceControllerStatus.Running)
			{
				return;
			}
			if (currentStatus == ServiceControllerStatus.StartPending)
			{
				service.WaitForStatus(ServiceControllerStatus.Running, ServiceOperationTimeout);
				return;
			}
			if (currentStatus == ServiceControllerStatus.StopPending)
			{
				service.WaitForStatus(ServiceControllerStatus.Stopped, ServiceOperationTimeout);
			}

			service.Refresh();
			service.Start();
			service.WaitForStatus(ServiceControllerStatus.Running, ServiceOperationTimeout);
		}

		private void StopTransportService()
		{
			lock (serviceMutex)
			{
				StopTransportServiceLocked();
			}
		}

		private void StopTransportServiceLocked()
		{
			ServiceControllerStatus currentStatus = GetTransportServiceStatus();
			if (currentStatus == ServiceControllerStatus.Stopped)
			{
				return;
			}
			if (currentStatus == ServiceControllerStatus.StopPending)
			{
				service.WaitForStatus(ServiceControllerStatus.Stopped, ServiceOperationTimeout);
				return;
			}
			if (currentStatus == ServiceControllerStatus.StartPending)
			{
				service.WaitForStatus(ServiceControllerStatus.Running, ServiceOperationTimeout);
			}

			service.Refresh();
			service.Stop();
			service.WaitForStatus(ServiceControllerStatus.Stopped, ServiceOperationTimeout);
		}

		/// <summary>
		/// Get the current status of Microsoft Exchange Transport service
		/// </summary>
		/// <returns>string</returns>
		public string GetStatus()
		{
			return status;
		}

		/// <summary>
		/// Execute a action (start, stop, restart) on Microsoft Exchange Transport service
		/// </summary>
		/// <param name="action">TransportServiceAction</param>
		public void Do(TransportServiceAction action, Action<string> errorCallback)
		{
			lock (actions)
			{
				if (disposed)
				{
					throw new ObjectDisposedException("TransportService");
				}

				switch (action)
				{
					case TransportServiceAction.Start:
					case TransportServiceAction.Stop:
						actions.Enqueue(new QueuedAction(action, errorCallback));
						break;
					case TransportServiceAction.Restart:
						actions.Enqueue(new QueuedAction(TransportServiceAction.Stop, errorCallback));
						actions.Enqueue(new QueuedAction(TransportServiceAction.Start, errorCallback));
						break;
					default:
						throw new ArgumentOutOfRangeException("action");
				}

				if (!workerRunning)
				{
					workerRunning = true;
					thread = new Thread(ExecuteAction)
					{
						IsBackground = true,
						Name = "Exchange DKIM Transport Service Worker"
					};
					thread.Start();
				}
			}
		}

		/// <summary>
		/// Dispose
		/// </summary>
		public void Dispose()
		{
			Thread worker;
			lock (actions)
			{
				disposed = true;
				worker = thread;
			}

			if (transportServiceStatus != null)
			{
				transportServiceStatus.Change(Timeout.Infinite, Timeout.Infinite);
				transportServiceStatus.Dispose();
				transportServiceStatus = null;
			}

			bool workerStopped = worker == null || !worker.IsAlive || worker.Join(WorkerShutdownTimeout);
			if (workerStopped)
			{
				thread = null;
				lock (serviceMutex)
				{
					if (service != null)
					{
						service.Dispose();
						service = null;
					}
				}
			}
		}
	}
}