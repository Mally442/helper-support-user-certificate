using BLL.BPC;
using BLL.DAL;
using BLL.Framework.Helpers;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Web;

public class UserHelper
{
	public SupportUserEntity CheckForSupportUserCertificate(Guid userId, HttpRequest request, out string errorMessage)
	{
		// If the user is not a support user, just return null
		if (!ContextProvider.IsSupportUser(userId))
		{
			errorMessage = "The user is not a support user";
			return null;
		}

		// Ensure that the support user is logging in at the support URL
		var urlHost = Resolver.Get<IAppSettingsHelper>().Get<string>("SUPPORT_HOST_URL");
		if (request.Url.Host != urlHost)
		{
			errorMessage = "Invalid username or password";
			return null;
		}

		// Ensure that the client certificate is present
		bool clientCertificatePresent = false;
		string commonName = null;

		string certificateString = request.Headers["X-Client-Cert"];
		if (!certificateString.IsNullOrEmpty())
		{
			// If the request is served via a proxy, the client certificate is passed through via a custom header
			clientCertificatePresent = true;
			var x509Certificate = new X509Certificate2(Encoding.UTF8.GetBytes(certificateString));
			commonName = x509Certificate.GetNameInfo(X509NameType.SimpleName, false);
		}
		else if (request.ClientCertificate.IsPresent)
		{
			// If the request is served purely by IIS, the client certificate can be accessed using the .NET request object
			clientCertificatePresent = true;
			commonName = request.ClientCertificate["SUBJECTCN"];
		}

		if (clientCertificatePresent == false)
		{
			errorMessage = "A certificate is required in order to login";
			return null;
		}

		if (commonName == null)
		{
			errorMessage = "Your certificate is missing crucial information";
			return null;
		}

		// Use the common name in the subject of the certificate to retrieve the support user
		var supportUserController = new SupportUserRepository();
		SupportUserEntity supportUser = supportUserController.Get(commonName);

		if (supportUser == null)
		{
			errorMessage = "Access has not been enabled for your certificate";
			return null;
		}

		errorMessage = string.Empty;
		return supportUser;
	}
}