using Exchange.DkimSigner.Configuration;
using Exchange.DkimSigner.Helper;
using Microsoft.Exchange.Data.Transport;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Exchange.DkimSigner
{
	/// <summary>
	/// Signs MIME messages according to the DKIM standard.
	/// </summary>
	public class DkimSigner
	{

		private sealed class DkimSettingsSnapshot
		{
			public Dictionary<string, DkimSigningContext> Domains { get; private set; }
			public HeaderId[] EligibleHeaders { get; private set; }

			public DkimSettingsSnapshot(Dictionary<string, DkimSigningContext> domains, HeaderId[] eligibleHeaders)
			{
				Domains = domains;
				EligibleHeaders = eligibleHeaders;
			}
		}

		internal sealed class DkimSigningContext
		{
			public DomainElementSigner DomainSigner { get; private set; }
			public HeaderId[] EligibleHeaders { get; private set; }
			public object SyncRoot { get; private set; }

			public DkimSigningContext(DomainElementSigner domainSigner, HeaderId[] eligibleHeaders)
			{
				DomainSigner = domainSigner;
				EligibleHeaders = (HeaderId[])eligibleHeaders.Clone();
				SyncRoot = new object();
			}
		}

		private volatile DkimSettingsSnapshot settingsSnapshot;
		private readonly object settingsUpdateMutex;

		/// <summary>
		/// Initializes a new instance of the <see cref="DkimSigner"/> class.
		/// </summary>
		public DkimSigner()
		{
			settingsSnapshot = new DkimSettingsSnapshot(new Dictionary<string, DkimSigningContext>(StringComparer.OrdinalIgnoreCase), new[] { HeaderId.From });
			settingsUpdateMutex = new object();
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Log general exceptions")]
		public void UpdateSettings(Settings config)
		{
			if (config == null)
			{
				throw new ArgumentNullException("config");
			}

			lock (settingsUpdateMutex)
			{
				Dictionary<string, DomainElementSigner> domains = new Dictionary<string, DomainElementSigner>(StringComparer.OrdinalIgnoreCase);

				DkimSignatureAlgorithm signatureAlgorithm;

				switch (config.SigningAlgorithm)
				{
					case DkimAlgorithmKind.RsaSha1:
						signatureAlgorithm = DkimSignatureAlgorithm.RsaSha1;
						break;
					case DkimAlgorithmKind.RsaSha256:
						signatureAlgorithm = DkimSignatureAlgorithm.RsaSha256;
						break;
					default:
						// ReSharper disable once NotResolvedInText
						throw new ArgumentOutOfRangeException("config.SigningAlgorithm");
				}

				DkimCanonicalizationAlgorithm bodyCanonicalization = config.BodyCanonicalization == DkimCanonicalizationKind.Relaxed ? DkimCanonicalizationAlgorithm.Relaxed : DkimCanonicalizationAlgorithm.Simple;
				DkimCanonicalizationAlgorithm headerCanonicalization = config.HeaderCanonicalization == DkimCanonicalizationKind.Relaxed ? DkimCanonicalizationAlgorithm.Relaxed : DkimCanonicalizationAlgorithm.Simple;

				foreach (DomainElement domainElement in config.Domains ?? new List<DomainElement>())
				{
					if (domainElement == null || string.IsNullOrWhiteSpace(domainElement.Domain) ||
						string.IsNullOrWhiteSpace(domainElement.Selector) || string.IsNullOrWhiteSpace(domainElement.PrivateKeyFile))
					{
						Logger.LogWarning("A domain setting is incomplete and will be ignored.");
						continue;
					}

					string domainName = domainElement.Domain.Trim().TrimEnd('.');
					if (domainName.Length == 0 || domains.ContainsKey(domainName))
					{
						Logger.LogWarning("Duplicate or invalid domain setting '" + domainElement.Domain + "'. This domain will be ignored.");
						continue;
					}

					string privateKey = domainElement.PrivateKeyPathAbsolute(
						Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
					if (String.IsNullOrEmpty(privateKey) || !File.Exists(privateKey))
					{
						Logger.LogError("The private key for domain " + domainName + " wasn't found: " + privateKey + ". Ignoring domain.");
						continue;
					}

					MimeKit.Cryptography.DkimSigner signer;
					try
					{
						AsymmetricKeyParameter key = KeyHelper.ParsePrivateKey(privateKey);

						signer = new MimeKit.Cryptography.DkimSigner(key, domainName, domainElement.Selector.Trim(), signatureAlgorithm)
						{
							BodyCanonicalizationAlgorithm = bodyCanonicalization,
							HeaderCanonicalizationAlgorithm = headerCanonicalization
						};
					}
					catch (Exception ex)
					{
						Logger.LogError("Could not initialize MimeKit DkimSigner for domain " + domainName + ": " + ex.Message);
						continue;
					}
					domains.Add(domainName, new DomainElementSigner(domainElement, signer));
				}

				List<HeaderId> headerList = new List<HeaderId>();
				foreach (string headerToSign in config.HeadersToSign ?? new List<string>())
				{
					if (!Enum.TryParse(headerToSign, true, out HeaderId headerId) || (headerId == HeaderId.Unknown))
					{
						Logger.LogWarning("Invalid value for header to sign: '" + headerToSign + "'. This header will be ignored.");
						continue;
					}
					if (IsProhibitedDkimHeader(headerId))
					{
						Logger.LogWarning("Header '" + headerToSign + "' cannot be included in a DKIM signature and will be ignored.");
						continue;
					}
					if (!headerList.Contains(headerId))
					{
						headerList.Add(headerId);
					}
				}

				// The From header must always be signed according to the DKIM specification.
				if (!headerList.Contains(HeaderId.From))
				{
					headerList.Add(HeaderId.From);
				}

				HeaderId[] eligibleHeaders = headerList.ToArray();
				Dictionary<string, DkimSigningContext> signingContexts = new Dictionary<string, DkimSigningContext>(StringComparer.OrdinalIgnoreCase);
				foreach (KeyValuePair<string, DomainElementSigner> domain in domains)
				{
					signingContexts.Add(domain.Key, new DkimSigningContext(domain.Value, eligibleHeaders));
				}

				settingsSnapshot = new DkimSettingsSnapshot(signingContexts, eligibleHeaders);
			}
		}

		private static bool IsProhibitedDkimHeader(HeaderId headerId)
		{
			switch (headerId)
			{
				case HeaderId.ReturnPath:
				case HeaderId.Received:
				case HeaderId.Comments:
				case HeaderId.Keywords:
				case HeaderId.Bcc:
				case HeaderId.ResentBcc:
				case HeaderId.DkimSignature:
					return true;
				default:
					return false;
			}
		}

		public int DomainCount
		{
			get { return settingsSnapshot.Domains.Count; }
		}

		public Dictionary<string, DomainElementSigner> GetDomains()
		{
			DkimSettingsSnapshot snapshot = settingsSnapshot;
			Dictionary<string, DomainElementSigner> result = new Dictionary<string, DomainElementSigner>(StringComparer.OrdinalIgnoreCase);
			foreach (KeyValuePair<string, DkimSigningContext> domain in snapshot.Domains)
			{
				result.Add(domain.Key, domain.Value.DomainSigner);
			}
			return result;
		}

		internal bool TryGetSigningContext(string domain, out DkimSigningContext signingContext)
		{
			return settingsSnapshot.Domains.TryGetValue(domain, out signingContext);
		}

		/// <summary>
		/// Signs the given mail item using the provided signer. The mailItem object will be updated so that it includes the signature.
		/// </summary>
		/// <param name="domainSigner">The domain and its signer</param>
		/// <param name="mailItem">The mail item to sign</param>
		public void SignMessage(DomainElementSigner domainSigner, MailItem mailItem)
		{
			if (domainSigner == null)
			{
				throw new ArgumentNullException("domainSigner");
			}

			DkimSettingsSnapshot snapshot = settingsSnapshot;
			SignMessage(new DkimSigningContext(domainSigner, snapshot.EligibleHeaders), mailItem);
		}

		internal void SignMessage(DkimSigningContext signingContext, MailItem mailItem)
		{
			if (signingContext == null)
			{
				throw new ArgumentNullException("signingContext");
			}
			if (mailItem == null)
			{
				throw new ArgumentNullException("mailItem");
			}

			// MailItem.GetMimeWriteStream() internally uses
			// Microsoft.Exchange.Data.Mime.MimeDocument.GetLoadStream(), which may reformat the
			// message using different formatting than is originally read from
			// MailItem.GetMimeReadStream().  To prevent these formatting changes from invalidating
			// the DKIM signature, we must read then write then re-read the message to ensure that
			// any formatting changes are made before we sign the message.
			using (MemoryStream memStream = new MemoryStream())
			{
				using (Stream inputStream = mailItem.GetMimeReadStream())
				{
					inputStream.Seek(0, SeekOrigin.Begin);
					inputStream.CopyTo(memStream);
				}
				memStream.Seek(0, SeekOrigin.Begin);
				using (Stream outputStream = mailItem.GetMimeWriteStream())
				{
					memStream.WriteTo(outputStream);
				}
			}

			using (Stream inputStream = mailItem.GetMimeReadStream())
			{
				inputStream.Seek(0, SeekOrigin.Begin);
				if (Logger.IsDebugEnabled())
				{
					Logger.LogDebug("Parsing the MimeMessage");
				}

				MimeMessage message = MimeMessage.Load(inputStream, true);
				// 'inputStream' cannot be disposed until we are done with 'message'

				if (Logger.IsDebugEnabled())
				{
					Logger.LogDebug("Signing the message");
				}

				lock (signingContext.SyncRoot)
				{
					signingContext.DomainSigner.Signer.Sign(message, signingContext.EligibleHeaders);
				}
				var value = message.Headers[HeaderId.DkimSignature];
				
				if (Logger.IsDebugEnabled())
				{
					Logger.LogDebug("Got signing header: " + value);
				}

				// The Stream returned by mailItem.GetMimeWriteStream() will throw an exception if
				// Stream.Write() is called after Stream.Flush() has been called, but
				// MimeMessage.WriteTo(FormatOptions, Stream) may call Stream.Flush() before the full
				// message has been written.  To avoid exceptions we must buffer the message in a
				// MemoryStream.
				using (MemoryStream memStream = new MemoryStream())
				{
					message.WriteTo(FormatOptions.Default, memStream);
					memStream.Seek(0, SeekOrigin.Begin);
					using (Stream outputStream = mailItem.GetMimeWriteStream())
					{
						memStream.WriteTo(outputStream);
					}
				}
			}
		}
	}
}