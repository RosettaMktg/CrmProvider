using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Services;
using System.Linq;
using System.Runtime.Serialization;
using System.Web;
using System.Web.Security;
using System.Web.Configuration;
using System.Collections.Specialized;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.IO;

using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Client;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Discovery;
using Microsoft.Xrm.Client.Services;
using Microsoft.Xrm.Sdk.Metadata;



public class CRMMembershipProvider : MembershipProvider
{
    /*CONSTANTS*/
    public class consts
    {
        private consts() {}
        /*Member variables*/
        public const string useraccount = "rosetta_useraccount";
        public const string appname = "rosetta_applicationname";
        public const string username = "rosetta_username";
        public const string name = "rosetta_name";
        public const string securityquestion = "rosetta_securityquestion";
        public const string email = "rosetta_email"; 
        public const string lockn = "rosetta_lock";
        public const string accountid = "rosetta_useraccountid";
        public const string deleteduser = "rosetta_deleteduser";
        public const string password = "rosetta_password";
        public const string securitypassword = "rosetta_securitypassword";
        public const string securityanswer = "rosetta_securityanswer";
        public const string online = "rosetta_online";
        public const string loginattempts = "rosetta_loginattempts";

        /*Activity variables*/
        public const string activities = "rosetta_activities";
        public const string activitytime = "rosetta_activitytime";
        public const string activityid = "activityid";
        public const string to = "to";
        public const string from= "from";
        public const string subject = "subject";
    }
    
    /*BEGINNING OF INITIALIZE FUNCTION*/
    protected string _ApplicationName;
    protected bool _EnablePasswordReset;
    protected bool _EnablePasswordRetrieval = false;
    protected bool _RequiresQuestionAndAnswer = false;
    protected bool _RequireUniqueEmail = true;
    protected int _MaxInvalidPasswordAttempts;
    protected int _PasswordAttemptWindow;
    protected int _MinRequiredPasswordLength;
    protected int _MinRequiredNonalphanumericCharacters;
    protected string _PasswordStrengthRegularExpression;
    protected MembershipPasswordFormat _PasswordFormat = MembershipPasswordFormat.Hashed;
    protected string _ConnectionStringName;

    protected string GetConfigValue(string configValue, string defaultValue)
    {
        if (string.IsNullOrEmpty(configValue))
            return defaultValue;
        return configValue;
    }
    public override void Initialize(string name, NameValueCollection config)
    {
        if (config == null)
            throw new ArgumentNullException("No configuration file found.");

        if (name == null || name.Length == 0)
            name = "CustomMembershipProvider";

        if (String.IsNullOrEmpty(config["description"]))
        {
            config.Remove("description");
            config.Add("description", "Custom Membership Provider");
        }

        base.Initialize(name, config);

        _ApplicationName = GetConfigValue(config["applicationName"],
                      System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
        _MaxInvalidPasswordAttempts = Convert.ToInt32(
                      GetConfigValue(config["maxInvalidPasswordAttempts"], "6"));
        _PasswordAttemptWindow = Convert.ToInt32(
                      GetConfigValue(config["passwordAttemptWindow"], "10"));
        _MinRequiredNonalphanumericCharacters = Convert.ToInt32(
                      GetConfigValue(config["minRequiredNonalphanumericCharacters"], "1"));
        _MinRequiredPasswordLength = Convert.ToInt32(
                      GetConfigValue(config["minRequiredPasswordLength"], "6"));
        _EnablePasswordReset = Convert.ToBoolean(
                      GetConfigValue(config["enablePasswordReset"], "true"));
        _PasswordStrengthRegularExpression = Convert.ToString(
                       GetConfigValue(config["passwordStrengthRegularExpression"], ""));
        _ConnectionStringName = Convert.ToString(
            GetConfigValue(config["connectionStringName"], "")); 
        if (_MaxInvalidPasswordAttempts < 0)
            throw new ConfigurationErrorsException("Must provide greater than 0 for max invalid password attempts in configuration file.");
        if (_ConnectionStringName == "")
            throw new ConfigurationErrorsException("Must provide connection string name in configuration file.");
    }

    /*CONNECTION AND QUERY*/
    protected OrganizationService OurConnect()
    {
        var connection = new CrmConnection(_ConnectionStringName);
        var service = new OrganizationService(connection);
        return service;
    }

    /*CONVERT STRING TP ASCI FOR ENCRYPT/DECRYPT*/
    static private byte[] StringToAscii(string password)
    {
        if (password != null)
        {
            byte[] newBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(password);
            return newBytes;
        }
        else
        {
            return new byte[0];
        }
            
    }

    private string ByteToUnicode(byte[] encodedPassword)
    {
        string str = System.Text.Encoding.Unicode.GetString(encodedPassword);

        return str;
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

                filter.Conditions.Add(subjectCondition);
            }
            else if (subject == "Locked")
            {
                ConditionExpression lockCondition = new ConditionExpression();

                lockCondition.AttributeName = consts.lockn;
                lockCondition.Operator = ConditionOperator.Equal;
                lockCondition.Values.Add(true);

                filter.Conditions.Add(lockCondition);
            }

            QueryExpression query = new QueryExpression(consts.activities);

            query.ColumnSet.AddColumn(consts.activitytime);
            query.AddOrder(consts.activitytime, OrderType.Descending);
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);
            return (DateTime)collection.Entities[0][consts.activitytime];
        }
    }

    /*STREAMLINE GETUSER PROCESS*/
    protected MembershipUser GetUser(string username)
    {
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression condition = new ConditionExpression(); //create new condition
            condition.AttributeName = consts.username; //column we want to check against
            condition.Operator = ConditionOperator.Equal; //checking against equal values
            condition.Values.Add(username); //check username against rosetta_username in CRM

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(condition); //add condition to the filter

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter); //query CRM with the new filter for username
            EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same username

            if (ec.Entities.Count != 0)
            {
                return null;
            }
            else
            {
                string _usernameN = (string)ec[0][consts.username];
                string _securityQuestionN = (string)ec[0][consts.securityquestion];
                string _emailN = (string)ec[0][consts.email];
                DateTime _timeLockedN = lastActivity(username, "Locked");
                DateTime _lastLoginTimeN = lastActivity(username, "Login");
                DateTime _accountCreationN = lastActivity(username, "Created On");
                DateTime _lastPasswordChangedDate = lastActivity(username, "Password Change");
                DateTime _lastAcivityDate = lastActivity(username, String.Empty);
                bool _lockN = (bool)ec[0][consts.lockn];
                Guid _accountId = (Guid)ec[0][consts.accountid];


                MembershipUser user = new MembershipUser("CRMMembershipProvider",
                                                          _usernameN,
                                                          _accountId,
                                                          _emailN,
                                                          _securityQuestionN,
                                                          String.Empty,
                                                          true,
                                                          _lockN,
                                                          _accountCreationN,
                                                          _lastLoginTimeN,
                                                          _lastAcivityDate,
                                                          _lastPasswordChangedDate,
                                                          _timeLockedN);
                return user;
            }
        }
    }

    /*MEMBERSHIP FUNCTIONS*/
    public override string ApplicationName
    {
        get{
            return _ApplicationName;
        }
        set{
            _ApplicationName = value;
        }
    }

    public override bool ChangePassword(string username, string oldPassword, string newPassword)
    {
        using (OrganizationService service = new OrganizationService(OurConnect()))
        { 
            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression passwordCondition = new ConditionExpression();

            usernameCondition.AttributeName = consts.username;
            usernameCondition.Operator = ConditionOperator.Equal;
            usernameCondition.Values.Add(username);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            passwordCondition.AttributeName = consts.password;
            passwordCondition.Operator = ConditionOperator.Equal;
            passwordCondition.Values.Add(EncryptPassword(StringToAscii(oldPassword)));

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(appCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(passwordCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumn(consts.password);
            query.ColumnSet.AddColumn(consts.username);
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0)
            {
                return false;
            }
            else
            { 
                collection.Entities[0]["rosetta_password"] = EncryptPassword(StringToAscii(oldPassword));
                collection.Entities[0][consts.password] = EncryptPassword(StringToAscii(oldPassword));
                activity(username, "Password Change", true);

                service.Update(collection.Entities[0]);
                return true;
            }
        }
    }

    public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
    {
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression passwordCondition = new ConditionExpression();

            usernameCondition.AttributeName = consts.username;
            usernameCondition.Operator = ConditionOperator.Equal;
            usernameCondition.Values.Add(username);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            passwordCondition.AttributeName = consts.password;
            passwordCondition.Operator = ConditionOperator.Equal;
            passwordCondition.Values.Add(EncryptPassword(StringToAscii(password)));

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(appCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(passwordCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumns(consts.securityquestion);
            query.ColumnSet.AddColumns(consts.securitypassword);
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0)
            {
                return false;
            }
            else
            {
                collection.Entities[0][consts.securityquestion] = newPasswordQuestion;
                collection.Entities[0][consts.securityanswer] = EncryptPassword(StringToAscii(newPasswordAnswer));

                service.Update(collection.Entities[0]);
                return true;
            }
        }
    }
    
    public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
    {
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

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.Criteria.AddFilter(filter); //query CRM with the new filter for username
            EntityCollection collection = service.RetrieveMultiple(query); //retrieve all records with same username

            if (collection.Entities.Count != 0)
            {
                status = MembershipCreateStatus.DuplicateUserName;
                return null;
            }
            else
            {
                if (_RequireUniqueEmail && GetUserNameByEmail(email) != null)
                {
                    status = MembershipCreateStatus.DuplicateEmail;
                    return null;
                }
                else
                {
                    if (providerUserKey == null)
                    {
                        providerUserKey = Guid.NewGuid();
                    }
                    else
                    {
                        if (!(providerUserKey is Guid))
                        {
                            status = MembershipCreateStatus.InvalidProviderUserKey;
                            return null;
                        }
                    }
                    Entity newMember = new Entity(consts.useraccount);
                    
                    newMember[consts.accountid] = providerUserKey;
                    newMember[consts.name] = "";
                    newMember[consts.username] = username;
                    newMember[consts.password] = ByteToUnicode(EncryptPassword(StringToAscii(password)));//Encoding.ASCII.GetString(EncryptPassword(StringToAsci(password)));
                    newMember[consts.email] = email;
                    newMember[consts.securityquestion] = passwordQuestion;
                    newMember[consts.securityanswer] = ByteToUnicode(EncryptPassword(StringToAscii(passwordAnswer)));
                    newMember[consts.appname] = _ApplicationName;
                    newMember[consts.deleteduser] = false;
                    newMember[consts.lockn] = false;
                    newMember[consts.online] = false;
                    newMember[consts.loginattempts] = 0;

                    Guid _accountID = service.Create(newMember);
                    status = MembershipCreateStatus.Success;
                    activity(username, "Created On", false);

                    return GetUser(username);
                }
            }
        }
    }
    
    protected override byte[] DecryptPassword(byte[] encodedPassword)
    {//cc
        MachineKeySection MCsection;

        Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None) as Configuration;

        MCsection = config.GetSection("system.web/machineKey") as MachineKeySection;

        if (_PasswordFormat == MembershipPasswordFormat.Hashed)
        {
            byte[] temp = MachineKey.Decode(ByteToUnicode(encodedPassword), MachineKeyProtection.Validation);
            
            return temp;
        }
            
        else if (_PasswordFormat == MembershipPasswordFormat.Encrypted)
        {
            byte[] temp = MachineKey.Decode(ByteToUnicode(encodedPassword), MachineKeyProtection.Encryption);

            return temp;
        }
        else
        {
            return encodedPassword;
        }
    }

    public override bool DeleteUser(string username, bool deleteAllRelatedData)
    {//tc
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            usernameCondition.AttributeName = consts.username;
            usernameCondition.Operator = ConditionOperator.Equal;
            usernameCondition.Values.Add(username);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumn(consts.username);
            query.ColumnSet.AddColumn(consts.deleteduser);
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);
            if (collection.Entities.Count == 0)
            {
                return false;
            }
            else
            {
                if (!deleteAllRelatedData)
                {
                    collection.Entities[0][consts.deleteduser] = true;
                    activity(username, "Deleted", true);
                    service.Update(collection.Entities[0]);
                    return true;
                }
                else
                {//hard delete
                    service.Delete(consts.useraccount, collection.Entities[0].Id);
                    return true;
                }
            }
        }
    }

    public override bool EnablePasswordReset
    {
        get { return _EnablePasswordReset; }
    }

    public override bool EnablePasswordRetrieval
    {
        get { return _EnablePasswordRetrieval; }
    }

    protected override byte[] EncryptPassword(byte[] password)
    {//cc
        
        MachineKeySection MCsection;

        Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None) as Configuration;

        MCsection = config.GetSection("system.web/machineKey") as MachineKeySection;

        if (_PasswordFormat == MembershipPasswordFormat.Hashed)
        {
            string temp = MachineKey.Encode(password, MachineKeyProtection.Validation);
            temp = MachineKey.Encode(StringToAscii(temp + MCsection.ValidationKey), MachineKeyProtection.Validation);
            temp = MachineKey.Encode(StringToAscii(MCsection.DecryptionKey + temp), MachineKeyProtection.Validation);

            return (StringToAscii(temp));
        }

        else if (_PasswordFormat == MembershipPasswordFormat.Encrypted)
        {
            string temp = MachineKey.Encode(password, MachineKeyProtection.Encryption);

            return (StringToAscii(temp));
        }
        else
        {
            return password;
        }
    }

    protected override byte[] EncryptPassword(byte[] password, MembershipPasswordCompatibilityMode legacyPasswordCompatibilityMode)
    {//cc
        MachineKeySection MCsection;

        Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None) as Configuration;

        MCsection = config.GetSection("system.web/machineKey") as MachineKeySection;

        if (legacyPasswordCompatibilityMode == MembershipPasswordCompatibilityMode.Framework40)
        {
            if (_PasswordFormat == MembershipPasswordFormat.Hashed)
            {
                string temp = MachineKey.Encode(password, MachineKeyProtection.Validation);
                temp = MachineKey.Encode(StringToAscii(temp + MCsection.ValidationKey), MachineKeyProtection.Validation);
                temp = MachineKey.Encode(StringToAscii(MCsection.DecryptionKey + temp), MachineKeyProtection.Validation);

                return (StringToAscii(temp));
            }

            else if (_PasswordFormat == MembershipPasswordFormat.Encrypted)
            {
                string temp = MachineKey.Encode(password, MachineKeyProtection.Encryption);

                return (StringToAscii(temp));
            }
            else
            {
                return password;
            }
        }
        else
        {
            MCsection.CompatibilityMode = MachineKeyCompatibilityMode.Framework20SP2;
            
            if (_PasswordFormat == MembershipPasswordFormat.Hashed)
            {
                string temp = MachineKey.Encode(password, MachineKeyProtection.Validation);
                temp = MachineKey.Encode(StringToAscii(temp + MCsection.ValidationKey), MachineKeyProtection.Validation);
                temp = MachineKey.Encode(StringToAscii(MCsection.DecryptionKey + temp), MachineKeyProtection.Validation);

                return (StringToAscii(temp));
            }

            else if (_PasswordFormat == MembershipPasswordFormat.Encrypted)
            {
                string temp = MachineKey.Encode(password, MachineKeyProtection.Encryption);

                return (StringToAscii(temp));
            }
            else
            {
                return password;
            }
        }
        
    }
    
    public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
    {//JH
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression emailCondition = new ConditionExpression(); //creates a new condition.
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            emailCondition.AttributeName = consts.email; //column we want to check against
            emailCondition.Operator = ConditionOperator.Equal; //checking against equal values
            emailCondition.Values.Add(emailToMatch); //checks email against rosetta_email in CRM

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(emailCondition); //add condition to the filter
            filter.Conditions.Add(deleteCondition); //add conditon 2 to the filter
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter); //query CRM with the new filter for email
            EntityCollection collection = service.RetrieveMultiple(query); //retrieve all records with same email

            totalRecords = collection.TotalRecordCount;

            if (totalRecords != 0 && totalRecords >= ((pageSize * pageIndex) + 1))
            {
                MembershipUserCollection usersToReturn = new MembershipUserCollection();
                var start = pageSize * pageSize;
                var end = (pageSize * pageSize) + (pageSize - (totalRecords % pageSize));
                for (int i = start; i < end; i++)
                {
                    MembershipUser TempUser = GetUser((string)collection.Entities[i][consts.username]);
                    usersToReturn.Add(TempUser);
                }
                return usersToReturn;
            }
            else
            {
                return null;
            }
        }
    }

    public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
    {//MAS
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();//creates a new condition.
            
            usernameCondition.AttributeName = consts.username; //column we want to check against
            usernameCondition.Operator = ConditionOperator.Equal; //checking against equal values
            usernameCondition.Values.Add(usernameToMatch); //checks email against rosetta_email in CRM

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);//add condition to the filter

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.Criteria.AddFilter(filter); //query CRM with the new filter for email
            EntityCollection collection = service.RetrieveMultiple(query); //retrieve all records with same email

            totalRecords = collection.TotalRecordCount;

            if (totalRecords != 0 && totalRecords >= ((pageSize * pageIndex) + 1))
            {
                MembershipUserCollection usersToReturn = new MembershipUserCollection();
                var start = pageSize * pageIndex;
                var end = (pageSize * pageIndex) + pageSize;
                for (int i = start; i < end; i++)//gets all the records out of ec assigns them to userstoreturn.
                {
                    MembershipUser TempUser = GetUser((string)collection.Entities[i][consts.username]);
                    usersToReturn.Add(TempUser);

                }
                return usersToReturn;
            }
            else
            {
                return null;
            }
        }
    }

    public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
    {//MAS
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            //TODO: reduce to one function?

            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();//creates a new condition.

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.Criteria.AddFilter(filter);
            EntityCollection collection = service.RetrieveMultiple(query); //retrieve all records with same email

            totalRecords = collection.TotalRecordCount;

            if (totalRecords != 0 && totalRecords >= ((pageSize * pageIndex) + 1))
            {
                MembershipUserCollection usersToReturn = new MembershipUserCollection();
                var start = pageSize * pageIndex;
                var end = (pageSize * pageIndex) + pageSize;
                for (int i = start; i < end; i++)
                {
                    MembershipUser TempUser = GetUser((string)collection.Entities[i][consts.username]);
                    usersToReturn.Add(TempUser);

                }
                return usersToReturn;
            }
            else
            {
                return null;
            }
        }
    }

    public override int GetNumberOfUsersOnline()
    {//JH
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression onlineCondition = new ConditionExpression();//creates a new condition.
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            //creates a new condition.
            onlineCondition.AttributeName = consts.online; //column we want to check against.
            onlineCondition.Operator = ConditionOperator.Equal;//sets the comparing. 
            onlineCondition.Values.Add(true);//check to see if users are online.

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(onlineCondition); //add condition to the filter
            filter.Conditions.Add(deleteCondition); //add conditon 2 to the filter
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.ColumnSet.AddColumn(consts.username);
            query.Criteria.AddFilter(filter); //query CRM with the new filter for users online 
            EntityCollection collection = service.RetrieveMultiple(query);

            return collection.TotalRecordCount;
        }
    }

    public override string GetPassword(string username, string answer)
    {//CC
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();
            ConditionExpression lockCondition = new ConditionExpression();
            
            usernameCondition.AttributeName = consts.username; //column to check against (trying to find username)
            usernameCondition.Operator = ConditionOperator.Equal; //checking agasint equal values
            usernameCondition.Values.Add(username); //check passed username value to password field in CRM

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            lockCondition.AttributeName = consts.lockn;
            lockCondition.Operator = ConditionOperator.Equal;
            lockCondition.Values.Add(false);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(usernameCondition); //add condition to filter
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);
            filter.Conditions.Add(lockCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter); //query CRM with the new filter for username
            EntityCollection collection = service.RetrieveMultiple(query); //retireve all records with same username

            if (collection.Entities.Count == 0) //check if any entities exist
            {
                return null;
            }
            else
            {
                if (EnablePasswordRetrieval) //if allowed to get password
                {
                    //hashed will return password
                    if (_RequiresQuestionAndAnswer == true) //checks if the answer to the security question is needed
                    {
                        if ((string)collection.Entities[0][consts.securityanswer] == answer) //TODO: (Curt) encrypt
                        {
                            return (string)collection.Entities[0][consts.password]; //TODO: (Curt) decrypt if not hashed
                        }
                        else
                        {
                            throw new MembershipPasswordException("Security answer given does not match that in CRM.");
                            //return null;
                        }
                    }
                    else
                    {
                        return (string)collection.Entities[0][consts.password]; //TODO: (Curt) decrypt if not hashed
                    }
                }
                else
                {
                    throw new NotSupportedException("Config file is configured to not allow password retrieval.");
                    //return null;
                }
            }
        }
    }

    public override MembershipUser GetUser(string username, bool userIsOnline)
    {//JH
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            usernameCondition.AttributeName = consts.username;
            usernameCondition.Operator = ConditionOperator.Equal;
            usernameCondition.Values.Add(username);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.Criteria.AddFilter(filter);
            query.ColumnSet.AllColumns = true;
            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0)
            {
                return null;
            }
            else
            {
                if (userIsOnline == (bool)collection.Entities[0][consts.online])
                    return GetUser((string)collection.Entities[0][consts.username]);
                return null;
            }
        }
    }

    public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
    {//MAS
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ColumnSet attributes = new ColumnSet(new string[] { consts.username, consts.online, consts.appname, consts.deleteduser });
            Entity e = service.Retrieve(consts.useraccount, (Guid)providerUserKey, attributes);

            if (userIsOnline == (bool)e[consts.online] && (string)e[consts.appname] == _ApplicationName && (bool)e[consts.deleteduser] == false)//TODO: make sure bool is casted
                return GetUser((string)e[consts.username]);
            return null;
        }
    }
    
    public override string GetUserNameByEmail(string email)
    {//bcd
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ConditionExpression emailCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            emailCondition.AttributeName = consts.email;
            emailCondition.Operator = ConditionOperator.Equal;
            emailCondition.Values.Add(email);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(emailCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumn(consts.username);
            query.Criteria.AddFilter(filter);
            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0)
                return null;
            else
            {
                Guid Retrieve_ID = collection[0].Id;
                ColumnSet attributies = new ColumnSet(new string[] { consts.username });
                Entity retrievedEntity = service.Retrieve(consts.useraccount, Retrieve_ID, attributies);

                return retrievedEntity[consts.username].ToString();
            }
        }     
    }

    public override int MaxInvalidPasswordAttempts
    {
        get { return _MaxInvalidPasswordAttempts; }
    }

    public override int MinRequiredNonAlphanumericCharacters
    {
        get { return _MinRequiredNonalphanumericCharacters; }
    }
   
    public override int MinRequiredPasswordLength
    {
        get { return _MinRequiredPasswordLength; } 
    }

    public override int PasswordAttemptWindow
    {
        get { return _PasswordAttemptWindow; }
    }

    public override MembershipPasswordFormat PasswordFormat
    {
        get { return _PasswordFormat; }
    }

    public override string PasswordStrengthRegularExpression
    {
        get { return _PasswordStrengthRegularExpression; }
    }

    public override bool RequiresQuestionAndAnswer
    {
        get { return _RequiresQuestionAndAnswer; }
    }

    public override bool RequiresUniqueEmail
    {
        get { return _RequireUniqueEmail; }
    }

    public override string ResetPassword(string username, string answer)
    {//bcd
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            if (!EnablePasswordReset)
            {
                throw new NotSupportedException("Config file has been set to not allow password reset");
                //return null;
            }
            else
            {//reset password based on assigned regular expresssion
                ConditionExpression usernameCondition = new ConditionExpression();
                ConditionExpression deleteCondition = new ConditionExpression();
                ConditionExpression appCondition = new ConditionExpression();
                ConditionExpression answerCondition = new ConditionExpression();

                usernameCondition.AttributeName = consts.username;
                usernameCondition.Operator = ConditionOperator.Equal;
                usernameCondition.Values.Add(username);

                deleteCondition.AttributeName = consts.deleteduser;
                deleteCondition.Operator = ConditionOperator.Equal;
                deleteCondition.Values.Add(false);

                appCondition.AttributeName = consts.appname;
                appCondition.Operator = ConditionOperator.Equal;
                appCondition.Values.Add(_ApplicationName);

                appCondition.AttributeName = consts.securitypassword;
                appCondition.Operator = ConditionOperator.Equal;
                appCondition.Values.Add(answer); //TODO: (Curt) encrypt

                FilterExpression filter = new FilterExpression();
                filter.Conditions.Add(usernameCondition);
                filter.Conditions.Add(deleteCondition);
                filter.Conditions.Add(appCondition);

                QueryExpression query = new QueryExpression(consts.useraccount);
                query.Criteria.AddFilter(filter);
                EntityCollection collection = service.RetrieveMultiple(query);

                if (collection.Entities.Count == 0)
                {
                    throw new MembershipPasswordException("The user's security answer is incorrect");
                    //return null;
                }
                else
                {
                    string NewPass = Membership.GeneratePassword(_MinRequiredPasswordLength, _MinRequiredNonalphanumericCharacters); //changed to have MinRequireNonalphanumericCharacters (CC)
                    collection.Entities[0][consts.securitypassword] = NewPass; //TODO: (Curt) encrypt 
                    service.Update(collection.Entities[0]);
                    activity(username, "Reset Password", true);

                    return NewPass;
                }
            }
        }
    }

    public override bool UnlockUser(string userName)
    {
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            usernameCondition.AttributeName = consts.username;
            usernameCondition.Operator = ConditionOperator.Equal;
            usernameCondition.Values.Add(userName);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumns(consts.lockn);
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0 || !(bool)collection.Entities[0][consts.lockn])
            {
                return false; //no user or already unlocked
            }
            else
            {
                collection.Entities[0][consts.lockn] = false;
                service.Update(collection.Entities[0]);
                activity(userName, "Unlocked", true);

                return true;
            }
        }
    }

    public override void UpdateUser(MembershipUser user)
    {//TC
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ConditionExpression guidCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            guidCondition.AttributeName = consts.accountid;
            guidCondition.Operator = ConditionOperator.Equal;
            guidCondition.Values.Add(user.ProviderUserKey);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(guidCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0)
            {
                return;
            }
            
            collection.Entities[0][consts.username] = user.UserName;
            collection.Entities[0][consts.securityquestion] = user.PasswordQuestion;
            collection.Entities[0][consts.email] = user.Email;
            collection.Entities[0][consts.lockn] = user.IsLockedOut;

            service.Update(collection.Entities[0]);
            activity(user.UserName, "", true);

            return;
        }
    }

    public override bool ValidateUser(string username, string password)
    {//bcd
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {
            ConditionExpression usernameCondition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();
            ConditionExpression lockCondition = new ConditionExpression();

            usernameCondition.AttributeName = consts.username;
            usernameCondition.Operator = ConditionOperator.Equal;
            usernameCondition.Values.Add(username);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.appname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            lockCondition.AttributeName = consts.lockn;
            lockCondition.Operator = ConditionOperator.Equal;
            lockCondition.Values.Add(false);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(usernameCondition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);
            filter.Conditions.Add(lockCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter);

            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0)
                return false;//the username does not exist

            if (!collection.Entities[0][consts.password].Equals(password)) //TODO: (Curt) encrypt(EncryptPassword(StringToAsci(password))))//user exists, but pass is wrong
            {
                ConditionExpression failedCondition = new ConditionExpression();
                ConditionExpression activitytimeCondition = new ConditionExpression();
               
                failedCondition.AttributeName = consts.subject;
                failedCondition.Operator = ConditionOperator.Equal;
                failedCondition.Values.Add("Failed Login");

                activitytimeCondition.AttributeName = consts.activitytime;
                activitytimeCondition.Operator = ConditionOperator.OnOrAfter;
                activitytimeCondition.Values.Add(DateTime.Now - DateTime.Now.AddMinutes(-(_PasswordAttemptWindow)));

                FilterExpression filter2 = new FilterExpression();
                filter2.Conditions.Add(activitytimeCondition);
               
                QueryExpression query2 = new QueryExpression(consts.useraccount);
                query2.ColumnSet.AllColumns = true;
                query2.Criteria.AddFilter(filter);

                EntityCollection collection2 = service.RetrieveMultiple(query);

                if(collection2.Entities.Count < _MaxInvalidPasswordAttempts)
                {
                    activity(username, "Failed Login", false);
                    collection.Entities[0][consts.loginattempts] = (int)collection.Entities[0][consts.loginattempts] + 1;
                }
                else if(collection2.Entities.Count ==  _MaxInvalidPasswordAttempts)
                {
                    activity(username, "Locked", true);
                    collection.Entities[0][consts.lockn] = true;
                    collection.Entities[0][consts.loginattempts] = 0;
                }

                service.Update(collection.Entities[0]);//update user information
                return false;
            }
            else
            {
                //reset attributes of login stuff
                collection.Entities[0][consts.online] = true;
                collection.Entities[0][consts.loginattempts] = 0;
                activity(username, "Login", false);

                service.Update(collection.Entities[0]);
                return true;
            }
        }
    }   
 
    private int checkPasswordReq(string password) //private function used to check that the passwords follow the requirements from the web.config
    {//CC
        //This function will return either 0, 1, 2, or 3. 
        //If a 1 is returned, the password did not meet minimum length.
        //If a 2 is returned, the password did not have enough NonAlphaNumeric characters
        //If a 3 is returned, the password did not match the Regular Expression
        //If a 0 is returned, then the password fit all criteria and is a valid password.

        if(password.Length < _MinRequiredPasswordLength) //check that the password is longer than MinRequiredPasswordLength
        {
            return 1; //if true, return error code 1
        }
        else
        {
            int nonAlphaNumCounter = 0;
            bool passedNonAlphaNum = false;

            for(int i=0; i<password.Length; i++)
            {
                if(!Char.IsLetterOrDigit(password, i)) //go through string and check if char is letter or digit
                {
                    nonAlphaNumCounter++; //if not, increment counter
                }
                if(nonAlphaNumCounter >= _MinRequiredNonalphanumericCharacters) //if counter is equal or greater to necessary
                {
                    passedNonAlphaNum = true; //say it passed
                    break; //break from loop
                }
            }

            if(!passedNonAlphaNum) //check bool on whether it passed or not
            {
                return 2; //if did not pass MinRequiredNonalphanumeric, return error code 2
            }

            if(_PasswordStrengthRegularExpression.Length > 0) //check to see if a regular expression is present
            {
                Regex passwordRegex = new Regex(_PasswordStrengthRegularExpression);
                if(!passwordRegex.IsMatch(password))
                {
                    return 3; //if password did not pass RegularExpression check, return error code 3
                }
            }

            return 0; //return 0 because password passed all checks
        }
    }
    
    /*
    protected virtual void passwordReq(string password)
    {
        int code = checkPasswordReq(password);

        if(code == 0)
        {
            return;
        }
        else if(code == 1)
        {
            throw new Exception("The password did not meet the require length.");
        }
        else if(code == 2)
        {
            throw new Exception("The password did not meet the minimum number of Non-AlphaNumeric characters.");
        }
        else if(code == 3)
        {
            throw new Exception("The password did not meet the requirements of the Regular Expression.");
        }

        return;
    }
    */
}

/*public sealed class MachineKeySection : ConfigurationSection
{

    public MachineKeySection()
    {

    }


    [ConfigurationProperty("validationKey",
     DefaultValue = "",
     IsRequired = true,
     IsKey = true)]
    public string ValidationKey
    {
        get
        {
            return (string)this["validationKey"];
        }
        set
        {
            this["validationKey"] = value;
        }
    }

    [ConfigurationProperty("decryptionKey",
        DefaultValue = "",
        IsRequired = true,
        IsKey = true)]
    public string DecryptionKey
    {
        get
        {
            return (string)this["decryptionKey"];
        }
        set
        {
            this["decryptionKey"] = value;
        }
    }

    [ConfigurationProperty("validation",
        DefaultValue = "HMACSHA256",
        IsRequired = false)]
    public string Validation
    {
        get
        {
            return (int)this["validation"];
        }
        set
        {
            this["validation"] = value;
        }
    }

    [ConfigurationProperty("decryption",
        DefaultValue = "AES",
        IsRequired = false)]
    public string Decryption
    {
        get
        {
            return (int)this["decryption"];
        }
        set
        {
            this["decryption"] = value;
        }
    }
}*/
