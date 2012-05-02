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
        /*Profile Variables*/
        public const string userprofile = "rosetta_userprofile";
        public const string appname = "rosetta_applicationname";
        public const string username = "rosetta_username";
        public const string isanonymous = "rosetta_isanonymous";
        public const string profileid = "rosetta_userprofileId";

        /*Activity Variables*/
        public const string activities = "rosetta_activities";
        public const string to = "rosetta_receivedby";
        public const string from = "rosetta_givenby";
        public const string activitytime = "createdon";
        public const string activityid = "activityid";
        public const string subject = "subject"; 
    }

    /*ACTIVITIES*/
    protected void activity(string username, string message, bool isUpdate)
    {
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            Entity newActivity = new Entity(consts.activities);

            newActivity[consts.activitytime] = DateTime.Now;
            newActivity[consts.activityid] = Guid.NewGuid();
            newActivity[consts.to] = username;
            newActivity[consts.from] = _ApplicationName;
            newActivity[consts.subject] = message;

            if (message != "")
                service.Create(newActivity);

            if (isUpdate)
            {
                newActivity[consts.subject] = "Modified";
                service.Create(newActivity);
            }

            return;
        }
    }

    protected DateTime lastActivity(string username, string subject)
    {
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ConditionExpression toCondition = new ConditionExpression();
            ConditionExpression fromCondition = new ConditionExpression();
            ConditionExpression subjectCondition = new ConditionExpression();

            toCondition.AttributeName = consts.to;
            toCondition.Operator = ConditionOperator.Equal;
            toCondition.Values.Add(username);

            fromCondition.AttributeName = consts.from;
            fromCondition.Operator = ConditionOperator.Equal;
            fromCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(toCondition);
            filter.Conditions.Add(fromCondition);
            

            if (subject != String.Empty)
            {
                subjectCondition.AttributeName = consts.subject;
                subjectCondition.Operator = ConditionOperator.Equal;
                subjectCondition.Values.Add(subject);
            }
            
            QueryExpression query = new QueryExpression(consts.activities);

            query.ColumnSet.AddColumn(consts.activitytime);
            query.AddOrder(consts.activitytime, OrderType.Descending);
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);
            return (DateTime)collection.Entities[0][consts.activitytime];
        }
    }

    private Guid GetUniqueID(string username, bool isAuthenticated, bool ignoreAuthenticationType)
    {
        if (username == null)
            throw new ArgumentNullException("User name cannot be null.");
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            usernameCondition.AttributeName = consts.username;
            usernameCondition.Operator = ConditionOperator.Equal;
            usernameCondition.Values.Add(username);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(appCondition);

            if (!ignoreAuthenticationType)
            {
                ConditionExpression isanonymousCondition = new ConditionExpression();

                isanonymousCondition.AttributeName = consts.isanonymous;
                isanonymousCondition.Operator = ConditionOperator.Equal;
                isanonymousCondition.Values.Add(!isAuthenticated);

                filter.Conditions.Add(isanonymousCondition);

            }

            QueryExpression query = new QueryExpression(consts.userprofile);
            query.ColumnSet.AddColumn(consts.profileid);
            query.Criteria.AddFilter(filter);
            EntityCollection collection = service.RetrieveMultiple(query);

            Guid uniqueID;
            if (collection.Entities.Count != 0)
                uniqueID = (Guid)collection.Entities[0][consts.profileid];
            else
            {
                Entity newProfile = new Entity(consts.userprofile);

                newProfile[consts.username] = username;
                newProfile[consts.appname] = _ApplicationName;
                newProfile[consts.isanonymous] = !isAuthenticated;

                uniqueID = (Guid)service.Create(newProfile);

                activity(username, "Profile Created", true);
            }

            return uniqueID;
        }
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
            name = "CustomProfileProvider";

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
            ConditionExpression authenticationCondition = new ConditionExpression();

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

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
            filter.Conditions.Add(authenticationCondition);

            QueryExpression query = new QueryExpression(consts.userprofile);
            query.ColumnSet.AddColumn(consts.username);
            query.Criteria.AddFilter(filter);
            EntityCollection collection = service.RetrieveMultiple(query);

            string[] usersToDelete = null;
            int j = 0;
            for(int i=0;i<collection.TotalRecordCount;i++)
            {
                if (DateTime.Compare(lastActivity((string)collection.Entities[i][consts.username], String.Empty), userInactiveSinceDate) < 0)
                {
                    usersToDelete[j] = (string)collection.Entities[i][consts.username];
                    j++;
                }
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

                lastActivityCondition.AttributeName = consts.subject;
                lastActivityCondition.Operator = ConditionOperator.NotBetween;
                lastActivityCondition.Values.Add(userInactiveSinceDate);
                lastActivityCondition.Values.Add(DateTime.Now);

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

            ProfileInfoCollection profiles = new ProfileInfoCollection();

            try
            {
                QueryExpression query = new QueryExpression(consts.userprofile);

                query.ColumnSet.AddColumn(consts.username);
                query.ColumnSet.AddColumn(consts.isanonymous);
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
                                                        lastActivity((string)collection.Entities[i][consts.username], String.Empty),
                                                        lastActivity((string)collection.Entities[i][consts.username], "Modified"),
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
                                                        lastActivity((string)collection.Entities[i][consts.username], String.Empty),
                                                        lastActivity((string)collection.Entities[i][consts.username], "Modified"),
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
        string username = (string)context["UserName"];

        SettingsPropertyValueCollection svc = new SettingsPropertyValueCollection();

        foreach (SettingsProperty prop in collection)
        {
            SettingsPropertyValue pv = new SettingsPropertyValue(prop);
            svc.Add(pv);
        }

        activity(username, "Got Property Values", false);

        return svc;
    }

    public override void  SetPropertyValues(System.Configuration.SettingsContext context, System.Configuration.SettingsPropertyValueCollection collection)
    {//JH
        string username = (string)context["UserName"];
        bool isAuthenticated = (bool)context["IsAuthenticated"];
        Guid uniqueID = GetUniqueID(username, isAuthenticated, false);

        SettingsPropertyValueCollection svc = new SettingsPropertyValueCollection();

        foreach (SettingsProperty prop in collection)
        {
            SettingsPropertyValue pv = new SettingsPropertyValue(prop);
            svc.Add(pv);
        }

        activity(username, "Set property values", false);
    }
}
