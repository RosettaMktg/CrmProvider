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
    /*CONSTANTS*/
    public class consts{
        private consts() {}
        //TODO: put these in CRM along with entity userprofile
        public const string userprofile = "rosetta_userprofile";
        public const string appname = "rosetta_applicationname";
        public const string username = "rosetta_username";
        public const string lastactivity = "rosetta_lastactivity";
        public const string lastupdated = "rosetta_lastupdated";
        public const string isanonymous = "rosetta_isanonymous";
    }
    
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
    {//MAS
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
           
            ConditionExpression appCondition = new ConditionExpression();
            ConditionExpression lastActivityCondition = new ConditionExpression();
            ConditionExpression authenticationCondition = new ConditionExpression();

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            lastActivityCondition.AttributeName = consts.lastactivity;
            lastActivityCondition.Operator = ConditionOperator.OnOrBefore;
            lastActivityCondition.Values.Add(userInactiveSinceDate);

            switch (authenticationOption)
            {
                case ProfileAuthenticationOption.Anonymous:
                    authenticationCondition.AttributeName = consts.isanonymous;
                    authenticationCondition.Operator = ConditionOperator.Equal;
                    authenticationCondition.Values.Add(true);
                    break;
                case ProfileAuthenticationOption.Authenticated:
                    authenticationCondition.AttributeName = consts.isanonymous;
                    authenticationCondition.Operator = ConditionOperator.Equal;
                    authenticationCondition.Values.Add(false);
                    break;
                default:
                    break;
            }

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(appCondition);
            filter.Conditions.Add(lastActivityCondition);
            filter.Conditions.Add(authenticationCondition);

            QueryExpression query = new QueryExpression(consts.userprofile);
            query.ColumnSet.AddColumn(consts.username);
            query.Criteria.AddFilter(filter);
            EntityCollection collection = service.RetrieveMultiple(query);

            string[] usersToDelete=null;
            for(int i=0; i<collection.TotalRecordCount; i++){
                usersToDelete[i]=(string)collection.Entities[i][consts.username];
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

                usernameCondition.AttributeName = consts.username;
                usernameCondition.Operator = ConditionOperator.Equal;
                usernameCondition.Values.Add(user);

                FilterExpression filter = new FilterExpression();
                filter.Conditions.Add(usernameCondition);

                QueryExpression query = new QueryExpression(consts.userprofile);
                query.ColumnSet.AddColumn(consts.username);
                query.Criteria.AddFilter(filter);
                EntityCollection collection = service.RetrieveMultiple(query);

               //TODO: throw exception if profile not found?

                service.Delete(consts.userprofile, collection.Entities[0].Id);
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

                usernameCondition.AttributeName = consts.username;
                usernameCondition.Operator = ConditionOperator.Equal;
                usernameCondition.Values.Add(p.UserName);

                FilterExpression filter = new FilterExpression();
                filter.Conditions.Add(usernameCondition);

                QueryExpression query = new QueryExpression(consts.userprofile);
                query.ColumnSet.AddColumn(consts.username);
                query.Criteria.AddFilter(filter);
                EntityCollection collection = service.RetrieveMultiple(query);

                service.Delete(consts.username, collection.Entities[0].Id);
                deletedProfiles++;
            }
            return deletedProfiles;
        }
    }

    //user made function for the next five functions to use
    private ProfileInfoCollection GetProfile(ProfileAuthenticationOption authenticationOption,
    string usernameToMatch, object userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
    {//MAS
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            //Retrieve all profiles.

            ConditionExpression appCondition = new ConditionExpression();

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(appCondition);

            // If searching for a user name to match, add the command text and parameters.

            if (usernameToMatch != null)
            {
                ConditionExpression usernameCondition = new ConditionExpression();
                
                usernameCondition.AttributeName = consts.username;
                usernameCondition.Operator = ConditionOperator.Equal;
                usernameCondition.Values.Add(usernameToMatch);

                filter.Conditions.Add(usernameCondition);
            }


            // If searching for inactive profiles, 
            // add the command text and parameters.

            if (userInactiveSinceDate != null)
            {
                ConditionExpression lastActivityCondition = new ConditionExpression();

                lastActivityCondition.AttributeName = consts.lastactivity;
                lastActivityCondition.Operator = ConditionOperator.OnOrBefore;
                lastActivityCondition.Values.Add(userInactiveSinceDate);

                filter.Conditions.Add(lastActivityCondition);
            }


            // If searching for a anonymous or authenticated profiles,    
            // add the command text and parameters.
            ConditionExpression authenticationCondition = new ConditionExpression();

            switch (authenticationOption)
            {
              case ProfileAuthenticationOption.Anonymous:
                authenticationCondition.AttributeName = consts.isanonymous;
                authenticationCondition.Operator = ConditionOperator.Equal;
                authenticationCondition.Values.Add(true);
                break;
              case ProfileAuthenticationOption.Authenticated:
                authenticationCondition.AttributeName = consts.isanonymous;
                authenticationCondition.Operator = ConditionOperator.Equal;
                authenticationCondition.Values.Add(false);
                break;
              default:
                break;
            }


            // Get the data.

            ProfileInfoCollection profiles = new ProfileInfoCollection();

            try
            {
                QueryExpression query = new QueryExpression(consts.userprofile);

                query.ColumnSet.AddColumn(consts.username);
                query.ColumnSet.AddColumn(consts.isanonymous);
                query.ColumnSet.AddColumn(consts.lastactivity);
                query.ColumnSet.AddColumn(consts.lastupdated);
                query.Criteria.AddFilter(filter);

                EntityCollection collection = service.RetrieveMultiple(query);

                totalRecords = collection.Entities.Count;

                if (totalRecords == 0) //No profiles
                    return null;
                else if (pageSize == 0)
                { //Count all profiles
                    for (int i = 0; i < totalRecords; i++)
                    {
                        ProfileInfo p = new ProfileInfo((string)collection.Entities[i][consts.username],
                                                        (bool)collection.Entities[i][consts.isanonymous],
                                                        (DateTime)collection.Entities[i][consts.lastactivity],
                                                        (DateTime)collection.Entities[i][consts.lastupdated],
                                                        0);
                        profiles.Add(p);
                    }
                    return profiles;
                }
                else
                { //All other functions
                    var start = pageSize * pageSize;
                    var end = (pageSize * pageSize) + (pageSize - (totalRecords % pageSize));
                    for (int i = start; i < end; i++)
                    {
                        ProfileInfo p = new ProfileInfo((string)collection.Entities[i][consts.username],
                                                        (bool)collection.Entities[i][consts.isanonymous],
                                                        (DateTime)collection.Entities[i][consts.lastactivity],
                                                        (DateTime)collection.Entities[i][consts.lastupdated],
                                                        0);
                        profiles.Add(p);
                    }
                    return profiles;
                }
            }

            catch (Exception e)
            {
                throw new Exception("Error in grabbing profiles.", e);//TODO: change exception type
            }
        }
    }

    private void CheckParameters(int pageIndex, int pageSize)
    {//MAS
        if (pageIndex < 0)
            throw new ArgumentException("Page index must 0 or greater.");
        if (pageSize < 1)
            throw new ArgumentException("Page size must be greater than 0.");
    }

    public override ProfileInfoCollection  FindInactiveProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
    {//MAC
        CheckParameters(pageIndex, pageSize);
        return GetProfile(authenticationOption, usernameToMatch, userInactiveSinceDate,
          pageIndex, pageSize, out totalRecords);
    }

    public override ProfileInfoCollection  FindProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
    {
        CheckParameters(pageIndex, pageSize);

        return GetProfile(authenticationOption, usernameToMatch,
            null, pageIndex, pageSize, out totalRecords);
    }

    public override ProfileInfoCollection  GetAllInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
    {
        CheckParameters(pageIndex, pageSize);

        return GetProfile(authenticationOption, null, userInactiveSinceDate,
              pageIndex, pageSize, out totalRecords);
    }

    public override ProfileInfoCollection  GetAllProfiles(ProfileAuthenticationOption authenticationOption, int pageIndex, int pageSize, out int totalRecords)
    {//MAS
        CheckParameters(pageIndex, pageSize);
        return GetProfile(authenticationOption, null, null,
          pageIndex, pageSize, out totalRecords);
    }

    public override int  GetNumberOfInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
    {
        int inactiveProfiles = 0;

        ProfileInfoCollection profiles =
          GetProfile(authenticationOption, null, userInactiveSinceDate,
              0, 0, out inactiveProfiles);

        return inactiveProfiles;
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
