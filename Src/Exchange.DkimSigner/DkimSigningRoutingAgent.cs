using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Routing;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Mail;
using System.Threading;

namespace Exchange.DkimSigner
{
	/// <summary>
	/// Signs outgoing MIME messages according to the DKIM protocol.
	/// </summary>
	public sealed class DkimSigningRoutingAgent : RoutingAgent
	{
		/// <summary>
		/// The object that knows how to sign messages.
		/// </summary>
		private readonly DkimSigner dkimSigner;

		private sealed class MessageEventState
		{
			public MessageEventState(AgentAsyncContext asyncContext, MailItem mailItem)
			{
				AsyncContext = asyncContext;
				MailItem = mailItem;
			}

			public AgentAsyncContext AsyncContext { get; private set; }

			public MailItem MailItem { get; private set; }
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="DkimSigningRoutingAgent"/> class.
		/// </summary>
		/// <param name="dkimSigner">The object that knows how to sign messages.</param>
		/// 
		public DkimSigningRoutingAgent(DkimSigner dkimSigner)
		{
			this.dkimSigner = dkimSigner;

			OnCategorizedMessage += WhenMessageCategorized;
		}

		/// <summary>
		/// Fired when Exchange has performed content conversion, if it was required.
		/// The OnCategorizedMessage event is the last event that fires before the server
		/// puts the message in the delivery queue. This means it's a good time to sign the
		/// message, because it's unlikely that anything else will diddle with the message
		/// and invalidate our signature. (Our transport agent will need to be the last to run,
		/// though.)
		/// </summary>
		/// <param name="source">The source.</param>
		/// <param name="e">The <see cref="Microsoft.Exchange.Data.Transport.Routing.QueuedMessageEventArgs"/> instance containing the event data.</param>
		private void WhenMessageCategorized(CategorizedMessageEventSource source, QueuedMessageEventArgs e)
		{
			if (Logger.IsDebugEnabled())
			{
				Logger.LogDebug("Got new message, checking if I can sign it...");
			}

			var state = new MessageEventState(GetAgentAsyncContext(), e.MailItem);
			ThreadPool.QueueUserWorkItem(new WaitCallback(HandleMessageEvent), state);
		}

		[SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Log general exceptions")]
		private void HandleMessageEvent(Object messageEventState)
		{
			var state = (MessageEventState)messageEventState;

			try
			{
				SignMailItem(state.MailItem);
			}
			catch (Exception ex)
			{
				Logger.LogError("Signing a mail item according to DKIM failed with an exception. Check the logged exception for details.\n" + ex);
			}
			finally
			{
				state.AsyncContext.Resume();
				state.AsyncContext.Complete();
			}
		}


		/// <summary>
		/// Signs the given mail item, if possible, according to the DKIM standard.
		/// </summary>
		/// <param name="mailItem">The mail item that is to be signed, if possible.</param>
		[SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Log general exceptions")]
		private void SignMailItem(MailItem mailItem)
		{
			// If the mail item is a "system message" then it will be read-only here,
			// and we can't sign it. Additionally, if the message has a "TnefPart",
			// then it is in a proprietary format used by Outlook and Exchange Server,
			// which means we shouldn't bother signing it.
			if (!mailItem.Message.IsSystemMessage && mailItem.Message.TnefPart == null)
			{
				string domainPart = null;

				/* Check if we have a valid From address */
				if (!mailItem.FromAddress.IsValid || mailItem.FromAddress.DomainPart == null)
				{
					// The FromAddress is empty. Try to get the domain from somewhere else (see https://github.com/Pro/dkim-exchange/issues/99)
					string smtpAddress = (mailItem.Message != null && mailItem.Message.Sender != null) ? mailItem.Message.Sender.SmtpAddress : null;
					if (!string.IsNullOrEmpty(smtpAddress))
					{
						try
						{
							domainPart = new MailAddress(smtpAddress).Host;
						}
						catch (FormatException)
						{
							// Ignore
						}
					}
					if (domainPart == null)
					{
						Logger.LogWarning("Invalid from address '" + mailItem.FromAddress + "' and invalid SmtpAddress '" + smtpAddress + "'. Not signing email.");
						return;
					}
				}
				else
				{
					// from address is valid
					domainPart = mailItem.FromAddress.DomainPart;
				}

				/* If domain was found in define domain configuration */
				if (dkimSigner.GetDomains().ContainsKey(domainPart))
				{
					try
					{
						dkimSigner.SignMessage(dkimSigner.GetDomains()[domainPart], mailItem);
					}
					catch (Exception ex)
					{
						Logger.LogError("Could not sign message: " + ex.Message);
					}

				}
				else 
				{
					if (Logger.IsDebugEnabled())
					{
						Logger.LogDebug("No entry found in config for domain '" + domainPart + "'");
					}
				}
			}
			else if (Logger.IsDebugEnabled())
			{
				Logger.LogDebug("Message is a System message or of TNEF format. Not signing.");
			}
		}
	}
}
