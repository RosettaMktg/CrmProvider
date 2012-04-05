using System;
using System.Web;
using System.Web.Profile;
using System.Collections.Specialized;
using System.Configuration;
using Microsoft.Xrm.Client.Services;
using Microsoft.Xrm.Client;

public class CRMProfileProvider : ProfileProvider
{
    /*BEGINNING OF INITIALIZE FUNCTION*/
    protected string _ApplicationName;
    protected string _ConnectionStringName;

    protected string GetConfigValue(string configValue, string defaultValue)
    {
        if (string.IsNullOrEmpty(configValue))
            return defaultValue;
        return configValue;
    }
    public override void Initialize(string name, NameValueCollection config)
    {//MAS
        if (config == null)
            throw new ArgumentNullException("No configuration file found.");

        if (name == null || name.Length == 0)
            name = "CustomMembershipProvider";

        if (String.IsNullOrEmpty(config["description"]))
        {
            config.Remove("description");
            config.Add("description", "Custom Profile Provider");
        }

        base.Initialize(name, config);

        _ApplicationName = GetConfigValue(config["applicationName"],
                      System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
        _ConnectionStringName = Convert.ToString(
            GetConfigValue(config["connectionStringName"], ""));
        if (_ConnectionStringName == "")
            throw new ConfigurationException("Must provide connection string name in configuration file.");
    }

    /*CONNECTION AND QUERY*/
    public OrganizationService OurConnect()
    {
        var connection = new CrmConnection(_ConnectionStringName);
        var service = new OrganizationService(connection);
        return service;
    }

    public override string ApplicationName
    {
        get
        {
            return _ApplicationName;
        }
        set
        {
            _ApplicationName = value;
        }
    } 

    public override int  DeleteInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
    {
 	    throw new NotImplementedException();
    }

    public override int  DeleteProfiles(string[] usernames)
    {
 	    throw new NotImplementedException();
    }

    public override int  DeleteProfiles(ProfileInfoCollection profiles)
    {
 	    throw new NotImplementedException();
    }

    public override ProfileInfoCollection  FindInactiveProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
    {
 	    throw new NotImplementedException();
    }

    public override ProfileInfoCollection  FindProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
    {
 	    throw new NotImplementedException();
    }

    public override ProfileInfoCollection  GetAllInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
    {
 	    throw new NotImplementedException();
    }

    public override ProfileInfoCollection  GetAllProfiles(ProfileAuthenticationOption authenticationOption, int pageIndex, int pageSize, out int totalRecords)
    {
 	    throw new NotImplementedException();
    }

    public override int  GetNumberOfInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
    {
 	    throw new NotImplementedException();
    }

    public override System.Configuration.SettingsPropertyValueCollection  GetPropertyValues(System.Configuration.SettingsContext context, System.Configuration.SettingsPropertyCollection collection)
    {
 	    throw new NotImplementedException();
    }

    public override void  SetPropertyValues(System.Configuration.SettingsContext context, System.Configuration.SettingsPropertyValueCollection collection)
    {
 	    throw new NotImplementedException();
    }
}
