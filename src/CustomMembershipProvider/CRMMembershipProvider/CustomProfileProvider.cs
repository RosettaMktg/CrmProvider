using System;
using System.Web;
using System.Web.Profile;
using System.Collections.Specialized;
using System.Configuration;
using Microsoft.Xrm.Client.Services;
using Microsoft.Xrm.Client;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk;

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
            throw new ConfigurationErrorsException("Must provide connection string name in configuration file.");
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
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
           
            ConditionExpression appCondition = new ConditionExpression();
            ConditionExpression lastActivityCondition = new ConditionExpression();
            ConditionExpression authenticationCondition = new ConditionExpression();

            appCondition.AttributeName = "rosetta_applicationname";
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            lastActivityCondition.AttributeName = "rosetta_lastactivity";
            lastActivityCondition.Operator = ConditionOperator.OnOrBefore;
            lastActivityCondition.Values.Add(userInactiveSinceDate);

            switch (authenticationOption)
            {
                case ProfileAuthenticationOption.Anonymous:
                    authenticationCondition.AttributeName = "rosetta_isauthenticated";
                    authenticationCondition.Operator = ConditionOperator.Equal;
                    authenticationCondition.Values.Add(false);
                    break;
                case ProfileAuthenticationOption.Authenticated:
                    authenticationCondition.AttributeName = "rosetta_isauthenticated";
                    authenticationCondition.Operator = ConditionOperator.Equal;
                    authenticationCondition.Values.Add(true);
                    break;
                default:
                    break;
            }

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(appCondition);
            filter.Conditions.Add(lastActivityCondition);
            filter.Conditions.Add(authenticationCondition);

            QueryExpression query = new QueryExpression("rosetta_userprofile");
            query.ColumnSet.AddColumn("rosetta_username");
            query.Criteria.AddFilter(filter);
            EntityCollection collection = service.RetrieveMultiple(query);

            string[] usersToDelete=null;
            for(int i=0; i<collection.TotalRecordCount; i++){
                usersToDelete[i]=(string)collection.Entities[i]["rosetta_username"];
            }

            return DeleteProfiles(usersToDelete);
        }
    }

    public override int  DeleteProfiles(string[] usernames)
    {//JH
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
           int deletedProfiles = 0;

           foreach(string user in usernames){
                ConditionExpression usernameCondition = new ConditionExpression();

                usernameCondition.AttributeName = "rosetta_username";
                usernameCondition.Operator = ConditionOperator.Equal;
                usernameCondition.Values.Add(user);

                FilterExpression filter = new FilterExpression();
                filter.Conditions.Add(usernameCondition);

                QueryExpression query = new QueryExpression("rosetta_userprofile");
                query.ColumnSet.AddColumn("rosetta_username");
                query.Criteria.AddFilter(filter);
                EntityCollection collection = service.RetrieveMultiple(query);

               //TODO: throw exception if profile not found?

                service.Delete("rosetta_userprofile", collection.Entities[0].Id);
                deletedProfiles++;
           }
           return deletedProfiles;
        }
    }

    public override int  DeleteProfiles(ProfileInfoCollection profiles)
    {//JH
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            int deletedProfiles = 0;

            foreach (ProfileInfo p in profiles)
            {
               
                ConditionExpression usernameCondition = new ConditionExpression();

                usernameCondition.AttributeName = "rosetta_username";
                usernameCondition.Operator = ConditionOperator.Equal;
                usernameCondition.Values.Add(p.UserName);

                FilterExpression filter = new FilterExpression();
                filter.Conditions.Add(usernameCondition);

                QueryExpression query = new QueryExpression("rosetta_userprofile");
                query.ColumnSet.AddColumn("rosetta_username");
                query.Criteria.AddFilter(filter);
                EntityCollection collection = service.RetrieveMultiple(query);

                //TODO: throw exception if profile not found?

                service.Delete("rosetta_userprofile", collection.Entities[0].Id);
                deletedProfiles++;
            }
            return deletedProfiles;
        }
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
    {//JH

        SettingsPropertyValueCollection values = new SettingsPropertyValueCollection();

        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            foreach (SettingsProperty property in collection)
            {
            
           
            
            }
        
        
        }
        
        
        
        
        
        
        throw new NotImplementedException();
    }

    public override void  SetPropertyValues(System.Configuration.SettingsContext context, System.Configuration.SettingsPropertyValueCollection collection)
    {//JH
 	    throw new NotImplementedException();
    }
}
