using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Specialized;
using System.Web;

namespace EmbedPBIApp.Controlelrs
{
    //NOTE: To get working with PBI Gov, see https://docs.microsoft.com/en-us/power-bi/developer/embed-sample-for-customers-us-govt
    [Authorize]
    public class HomeController : Controller
    {
        private readonly AzureAdOptions _azureAdOptions;
        private readonly string _catchCodeUrl;

        public HomeController(IOptions<AzureAdOptions> azureAdOptions)
        {
            _azureAdOptions = azureAdOptions.Value;            
        }

        // GET: /<controller>/
        public IActionResult Index([FromQuery]string reportId, [FromQuery]string groupId, [FromQuery]string filterPaneEnabled, [FromQuery]string navContentPaneEnabled)
        {
            var token = GetAccessToken();
            if (token == null)
            {
                return GetAuthorizationCode();
            }

            var boolFilterPaneEnabled = ConvertAnyStringToBoolean(filterPaneEnabled);
            var boolNavContentPaneEnabled = ConvertAnyStringToBoolean(navContentPaneEnabled);

            var embedUrl = $"{_azureAdOptions.EmbedUrlBase}/reportEmbed?reportId={reportId}";
            if (groupId != null)
            {
                embedUrl += $"&groupId={groupId}";
            }
            
            ViewData["FilterPaneEnabled"] = boolFilterPaneEnabled;           
            ViewData["NavContentPaneEnabled"] = boolNavContentPaneEnabled;
            ViewData["Token"] = token;
            ViewData["EmbedUrl"] = embedUrl;       

            return View();
        }

        private static bool ConvertAnyStringToBoolean(string stringToConvert)
        {
            if (stringToConvert != null)
            {
                try
                {
                    return Convert.ToBoolean(stringToConvert);
                }
                catch (Exception)
                {
                    return false;
                }
            }
            return false;
        }

        public IActionResult CatchCode([FromQuery]string code, [FromQuery]string state) // This is where AAD will redirect back to after GetAuthorizationCode() is called
        {
            // ADAL will cached the token so that calls to AcquireTokenSilentAsync will get the token from the cache
            // if it hasn't expired.  So we don't need to put it in something like session.
            var token = GetAccessToken(code);
            return Redirect(Url.Action(nameof(HomeController.Index)) + state); // Redirect back to home so we don't see the code on the url
        }

        private string GetAccessToken() // TODO: investigate whether it makes sense to use a more robust token cache provider for ADAL
        {
            var authContext = new AuthenticationContext(_azureAdOptions.Instance);
            var userIdentifier = new UserIdentifier(User.Identity.Name, UserIdentifierType.RequiredDisplayableId);
            var clientCredential = new ClientCredential(_azureAdOptions.ClientId, _azureAdOptions.ClientSecret);
            string token = null;
            try
            {
                token = authContext.AcquireTokenSilentAsync(
                            _azureAdOptions.Resource, clientCredential, userIdentifier
                        ).Result.AccessToken;
            }
            catch (Exception e)
            {
                // eat it
            }
            return token;
        }

        private string GetAccessToken(string authorizationCode)
        {
            var authContext = new AuthenticationContext(_azureAdOptions.Instance);
            var clientCredential = new ClientCredential(_azureAdOptions.ClientId, _azureAdOptions.ClientSecret);
            var catchCodeUrl = Url.Action(nameof(HomeController.CatchCode), "Home", values: null, protocol: Request.Scheme);

            //Set token from authentication result
            return authContext.AcquireTokenByAuthorizationCodeAsync(
                        authorizationCode,
                        new Uri(catchCodeUrl),
                        clientCredential
                    ).Result.AccessToken;
        }

        private RedirectResult GetAuthorizationCode()
        {
            var catchCodeUrl = Url.Action(nameof(HomeController.CatchCode), "Home", values: null, protocol: Request.Scheme);
            var @params = new NameValueCollection
            {
                {"response_type", "code"},
                {"client_id", _azureAdOptions.ClientId},
                {"resource", _azureAdOptions.Resource}, //PBI
                { "redirect_uri", catchCodeUrl},
                { "state", Request.QueryString.Value}
            };

            //Create sign-in query string
            var queryString = HttpUtility.ParseQueryString(string.Empty);
            queryString.Add(@params);

            //Redirect to Azure AD to get an authorization code
            return Redirect($"{_azureAdOptions.Instance}/oauth2/authorize/?{queryString}");
        }
    }
}