﻿using System;
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

using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Client;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Discovery;
using Microsoft.Xrm.Client.Services;
using Microsoft.Xrm.Sdk.Metadata;



public class CRMMembershipProvider : MembershipProvider
{
    public class consts
    {
        private consts() { }
        public const string username = "rosetta_username";
        public const string useraccount = "rosetta_useraccount";
        public const string securityquestion = "rosetta_securityquestion";
        public const string email = "rosetta_email";
        public const string timelocked = "rosetta_timelocked";
        public const string lastlogin = "rosetta_lastlogin";
        public const string accountcreation = "rosetta_accountcreation";
        public const string lockn = "rosetta_lock";
        public const string accountid = "rosetta_useraccountid";
        public const string applicationname = "rosetta_applicationname";
        public const string deleteduser = "rosetta_deleteduser";
        public const string password = "rosetta_password";
        public const string securitypassword = "rosetta_securitypassword";
        public const string securityanswer = "rosetta_securityanswer";
        public const string online = "rosetta_online";
        public const string loginattempts = "rosetta_loginattempts";
        public const string firstfailed = "rosetta_firstfailed";

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
    {//MAS
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
                      GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
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
    public OrganizationService OurConnect()
    {
        var connection = new CrmConnection(_ConnectionStringName);
        var service = new OrganizationService(connection);
        return service;
    }

    /*CONVERT STRING TP ASCI FOR ENCRYPT/DECRYPT*/
    static private byte[] StringToAsci(string password)
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

    /*STREAMLINE GETUSER PROCESS*/
    protected MembershipUser GetUser(string username)
    {//MAS
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
                DateTime _timeLockedN = (DateTime)ec[0][consts.timelocked];
                DateTime _lastLoginTimeN = (DateTime)ec[0][consts.lastlogin];
                DateTime _accountCreationN = (DateTime)ec[0][consts.accountcreation];
                DateTime _lastPasswordChangedDate = DateTime.Now;//TODO: change to activities, seperate entity
                DateTime _lastAcivityDate = DateTime.Now;
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
    {//tc
        using (OrganizationService service = new OrganizationService(OurConnect()))
        { 
            ConditionExpression c = new ConditionExpression();
            ConditionExpression c2 = new ConditionExpression();
            ConditionExpression c3 = new ConditionExpression();
            ConditionExpression c4 = new ConditionExpression();

            c.AttributeName = consts.username;
            c.Operator = ConditionOperator.Equal;
            c.Values.Add(username);

            c2.AttributeName = consts.applicationname;
            c2.Operator = ConditionOperator.Equal;
            c2.Values.Add(_ApplicationName);

            c3.AttributeName = consts.deleteduser;
            c3.Operator = ConditionOperator.Equal;
            c3.Values.Add(false);

            c4.AttributeName = consts.password;
            c4.Operator = ConditionOperator.Equal;
            c4.Values.Add(EncryptPassword(StringToAsci(oldPassword)));

            FilterExpression f = new FilterExpression();
            f.Conditions.Add(c);
            f.Conditions.Add(c2);
            f.Conditions.Add(c3);
            f.Conditions.Add(c4);

            QueryExpression q = new QueryExpression(consts.useraccount);
            q.ColumnSet.AddColumn(consts.password);
            q.ColumnSet.AddColumn(consts.username);
            q.Criteria.AddFilter(f);

            EntityCollection ec = service.RetrieveMultiple(q);

            if (ec.Entities.Count == 0)
            {
                //if username doesn't exist
                return false;
            }
            else
            { 
                ec.Entities[0][consts.password] = EncryptPassword(StringToAsci(oldPassword));

                service.Update(ec.Entities[0]);
                return true;
            }
        }
    }

    public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
    {//bcd
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression c = new ConditionExpression();
            ConditionExpression c2 = new ConditionExpression();
            ConditionExpression c3 = new ConditionExpression();
            ConditionExpression c4 = new ConditionExpression();

            c.AttributeName = consts.username;
            c.Operator = ConditionOperator.Equal;
            c.Values.Add(username);

            c2.AttributeName = consts.applicationname;
            c2.Operator = ConditionOperator.Equal;
            c2.Values.Add(_ApplicationName);

            c3.AttributeName = consts.deleteduser;
            c3.Operator = ConditionOperator.Equal;
            c3.Values.Add(false);

            c4.AttributeName = consts.password;
            c4.Operator = ConditionOperator.Equal;
            c4.Values.Add(EncryptPassword(StringToAsci(password)));

            FilterExpression f = new FilterExpression();
            f.Conditions.Add(c);
            f.Conditions.Add(c2);
            f.Conditions.Add(c3);
            f.Conditions.Add(c4);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumns(consts.securityquestion);
            query.ColumnSet.AddColumns(consts.securitypassword);
            query.Criteria.AddFilter(f);

            EntityCollection ec = service.RetrieveMultiple(query);

            if (ec.Entities.Count == 0)
            {
                //user doesn't exist
                return false;
            }
            else
            {
                ec.Entities[0][consts.securityquestion] = EncryptPassword(StringToAsci(newPasswordQuestion));
                ec.Entities[0][consts.securityanswer] = EncryptPassword(StringToAsci(newPasswordAnswer));

                service.Update(ec.Entities[0]);//success
                return true;
            }
        }
    }
    
    public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
    {//MAS
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression c = new ConditionExpression();
            ConditionExpression c2 = new ConditionExpression();
            ConditionExpression c3 = new ConditionExpression();
            ConditionExpression c4 = new ConditionExpression();
            c.AttributeName = consts.username;
            c.Operator = ConditionOperator.Equal;
            c.Values.Add(username);

            c2.AttributeName = consts.applicationname;
            c2.Operator = ConditionOperator.Equal;
            c2.Values.Add(_ApplicationName);

            c3.AttributeName = consts.deleteduser;
            c3.Operator = ConditionOperator.Equal;
            c3.Values.Add(false);

            c4.AttributeName = consts.password;
            c4.Operator = ConditionOperator.Equal;
            c4.Values.Add(EncryptPassword(StringToAsci(password)));

            FilterExpression f = new FilterExpression();
            f.Conditions.Add(c);
            f.Conditions.Add(c2);
            f.Conditions.Add(c3);
            f.Conditions.Add(c4);


            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.Criteria.AddFilter(f); //query CRM with the new filter for username
            EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same username

            if (ec.Entities.Count != 0)
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
                    newMember["rosetta_name"] = username;
                    newMember[consts.username] = username;
                    newMember[consts.password] = ByteToUnicode(EncryptPassword(StringToAsci(password)));//Encoding.ASCII.GetString(EncryptPassword(StringToAsci(password)));
                    newMember[consts.email] = email;
                    newMember[consts.securityquestion] = ByteToUnicode(EncryptPassword(StringToAsci(passwordQuestion)));
                    newMember[consts.securityanswer] = ByteToUnicode(EncryptPassword(StringToAsci(passwordAnswer)));
                    newMember[consts.applicationname] = _ApplicationName;
                    newMember[consts.deleteduser] = false;
                    newMember[consts.lockn] = false;
                    newMember[consts.online] = false;
                    newMember[consts.loginattempts] = 0;
                    newMember[consts.accountcreation] = DateTime.Now;
                    newMember[consts.firstfailed] = DateTime.Now;
                    newMember[consts.lastlogin] = DateTime.Now;
                    newMember[consts.timelocked] = DateTime.Now;

                    Guid _accountID = service.Create(newMember);
                    status = MembershipCreateStatus.Success;

                    return GetUser(username);
                }
            }
        }
    }
    
    /*protected override byte[] DecryptPassword(byte[] encodedPassword)
    {
        
        return base.DecryptPassword(encodedPassword);
    }*/

    public override bool DeleteUser(string username, bool deleteAllRelatedData)
    {//tc
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression c = new ConditionExpression();
            ConditionExpression c2 = new ConditionExpression();

            c.AttributeName = consts.username;
            c.Operator = ConditionOperator.Equal;
            c.Values.Add(username);

            c2.AttributeName = consts.applicationname;
            c2.Operator = ConditionOperator.Equal;
            c2.Values.Add(_ApplicationName);

            FilterExpression f = new FilterExpression();
            f.Conditions.Add(c);
            f.Conditions.Add(c2);

            QueryExpression q = new QueryExpression(consts.useraccount);
            q.ColumnSet.AddColumn(consts.username);
            q.ColumnSet.AddColumn(consts.deleteduser);
            q.Criteria.AddFilter(f);

            EntityCollection ec = service.RetrieveMultiple(q);
            if (ec.Entities.Count == 0)
            {
                return false;
            }
            else
            {
                if (deleteAllRelatedData == false)
                {
                    if ((bool)ec.Entities[0][consts.deleteduser])
                    {
                        return false;
                    }
                    else
                    {//soft delete
                        ec.Entities[0][consts.deleteduser] = true;
                        service.Update(ec.Entities[0]);
                        return true;
                    }
                }
                else
                {//hard delete
                    service.Delete(consts.useraccount, ec.Entities[0].Id);
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

    /*protected override byte[] EncryptPassword(byte[] password)
    {
        return base.EncryptPassword(password);
    }

    protected override byte[] EncryptPassword(byte[] password, MembershipPasswordCompatibilityMode legacyPasswordCompatibilityMode)
    {
        return base.EncryptPassword(password, legacyPasswordCompatibilityMode);
    }*/
    
    public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
    {//JH
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression condition = new ConditionExpression(); //creates a new condition.
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            condition.AttributeName = consts.email; //column we want to check against
            condition.Operator = ConditionOperator.Equal; //checking against equal values
            condition.Values.Add(emailToMatch); //checks email against rosetta_email in CRM

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(condition); //add condition to the filter
            filter.Conditions.Add(deleteCondition); //add conditon 2 to the filter
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter); //query CRM with the new filter for email
            EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same email

            totalRecords = ec.TotalRecordCount;

            if (totalRecords != 0 && totalRecords >= ((pageSize * pageIndex) + 1))
            {
                MembershipUserCollection usersToReturn = new MembershipUserCollection();
                var start = pageSize * pageSize;
                var end = (pageSize * pageSize) + (pageSize - (totalRecords % pageSize));
                for (int i = start; i < end; i++)
                {
                    MembershipUser TempUser = GetUser((string)ec.Entities[i][consts.username]);
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

            ConditionExpression condition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();//creates a new condition.
            condition.AttributeName = consts.username; //column we want to check against
            condition.Operator = ConditionOperator.Equal; //checking against equal values
            condition.Values.Add(usernameToMatch); //checks email against rosetta_email in CRM

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(condition);
            filter.Conditions.Add(condition);
            filter.Conditions.Add(condition);//add condition to the filter

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.Criteria.AddFilter(filter); //query CRM with the new filter for email
            EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same email

            totalRecords = ec.TotalRecordCount;

            if (totalRecords != 0 && totalRecords >= ((pageSize * pageIndex) + 1))
            {
                MembershipUserCollection usersToReturn = new MembershipUserCollection();
                var start = pageSize * pageIndex;
                var end = (pageSize * pageIndex) + pageSize;
                for (int i = start; i < end; i++)//gets all the records out of ec assigns them to userstoreturn.
                {
                    MembershipUser TempUser = GetUser((string)ec.Entities[i][consts.username]);
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

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.Criteria.AddFilter(filter);
            EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same email

            totalRecords = ec.TotalRecordCount;

            if (totalRecords != 0 && totalRecords >= ((pageSize * pageIndex) + 1))
            {
                MembershipUserCollection usersToReturn = new MembershipUserCollection();
                var start = pageSize * pageIndex;
                var end = (pageSize * pageIndex) + pageSize;
                for (int i = start; i < end; i++)
                {
                    MembershipUser TempUser = GetUser((string)ec.Entities[i][consts.username]);
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

            ConditionExpression condition = new ConditionExpression();//creates a new condition.
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            //creates a new condition.
            condition.AttributeName = consts.online; //column we want to check against.
            condition.Operator = ConditionOperator.Equal;//sets the comparing. 
            condition.Values.Add(true);//check to see if users are online.

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(condition); //add condition to the filter
            filter.Conditions.Add(deleteCondition); //add conditon 2 to the filter
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.ColumnSet.AddColumn(consts.username);
            query.Criteria.AddFilter(filter); //query CRM with the new filter for users online 
            EntityCollection ec = service.RetrieveMultiple(query);

            return ec.TotalRecordCount;
        }
    }

    public override string GetPassword(string username, string answer)
    {//CC
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression condition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();
            ConditionExpression lockCondition = new ConditionExpression();
            //creates a new condition
            condition.AttributeName = consts.username; //column to check against (trying to find username)
            condition.Operator = ConditionOperator.Equal; //checking agasint equal values
            condition.Values.Add(username); //check passed username value to password field in CRM

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            lockCondition.AttributeName = consts.lockn;
            lockCondition.Operator = ConditionOperator.Equal;
            lockCondition.Values.Add(false);

            FilterExpression filter = new FilterExpression(); //create new filter for the condition
            filter.Conditions.Add(condition); //add condition to filter
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);
            filter.Conditions.Add(lockCondition);

            QueryExpression query = new QueryExpression(consts.useraccount); //create new query
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter); //query CRM with the new filter for username
            EntityCollection ec = service.RetrieveMultiple(query); //retireve all records with same username

            if (ec.Entities.Count == 0) //check if any entities exist
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
                        if ((string)ec.Entities[0][consts.securityanswer] == answer) //TODO: (Curt) encrypt
                        {
                            return (string)ec.Entities[0][consts.password]; //TODO: (Curt) decrypt if not hashed
                        }
                        else
                        {
                            throw new MembershipPasswordException("Security answer given does not match that in CRM.");
                            //return null;
                        }
                    }
                    else
                    {
                        return (string)ec.Entities[0][consts.password]; //TODO: (Curt) decrypt if not hashed
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

            ConditionExpression condition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            condition.AttributeName = consts.username;
            condition.Operator = ConditionOperator.Equal;
            condition.Values.Add(username);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(condition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.Criteria.AddFilter(filter);
            query.ColumnSet.AllColumns = true;
            EntityCollection ec = service.RetrieveMultiple(query);

            if (ec.Entities.Count == 0)
            {
                return null;
            }
            else
            {
                if (userIsOnline == (bool)ec.Entities[0][consts.online])
                    return GetUser((string)ec.Entities[0][consts.username]);
                return null;
            }
        }
    }

    public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
    {//MAS
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ColumnSet attributes = new ColumnSet(new string[] { consts.username, consts.online, consts.applicationname, consts.deleteduser });
            Entity e = service.Retrieve(consts.useraccount, (Guid)providerUserKey, attributes);

            if (userIsOnline == (bool)e[consts.online] && (string)e[consts.applicationname] == _ApplicationName && (bool)e[consts.deleteduser] == false)//TODO: make sure bool is casted
                return GetUser((string)e[consts.username]);
            return null;
        }
    }
    
    public override string GetUserNameByEmail(string email)
    {//bcd
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression condition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            condition.AttributeName = consts.email;
            condition.Operator = ConditionOperator.Equal;
            condition.Values.Add(email);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(condition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumn(consts.username);
            query.Criteria.AddFilter(filter);
            EntityCollection collection = service.RetrieveMultiple(query);

            if (collection.Entities.Count == 0)
                return null;
            else//return username
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
                ConditionExpression condition = new ConditionExpression();
                ConditionExpression deleteCondition = new ConditionExpression();
                ConditionExpression appCondition = new ConditionExpression();

                condition.AttributeName = consts.username;
                condition.Operator = ConditionOperator.Equal;
                condition.Values.Add(username);

                deleteCondition.AttributeName = consts.deleteduser;
                deleteCondition.Operator = ConditionOperator.Equal;
                deleteCondition.Values.Add(false);

                appCondition.AttributeName = consts.applicationname;
                appCondition.Operator = ConditionOperator.Equal;
                appCondition.Values.Add(_ApplicationName);

                FilterExpression filter = new FilterExpression();
                filter.Conditions.Add(condition);
                filter.Conditions.Add(deleteCondition);
                filter.Conditions.Add(appCondition);

                QueryExpression query = new QueryExpression(consts.useraccount);
                query.ColumnSet.AddColumn(consts.securityanswer);
                query.Criteria.AddFilter(filter);
                EntityCollection ec = service.RetrieveMultiple(query);

                if (ec.Entities.Count == 0)
                {
                    throw new MembershipPasswordException("The user's security answer is incorrect");
                    //return null;
                }
                else
                {
                    string NewPass = Membership.GeneratePassword(_MinRequiredPasswordLength, _MinRequiredNonalphanumericCharacters); //changed to have MinRequireNonalphanumericCharacters (CC)
                    ec.Entities[0][consts.password] = NewPass;
                    service.Update(ec.Entities[0]);
                    return NewPass;
                }
            }
        }
    }

    public override bool UnlockUser(string userName)
    {
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression condition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            condition.AttributeName = consts.username;
            condition.Operator = ConditionOperator.Equal;
            condition.Values.Add(userName);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(condition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AddColumns(consts.lockn);
            query.Criteria.AddFilter(filter);

            EntityCollection ec = service.RetrieveMultiple(query);

            if (ec.Entities.Count == 0 || !(bool)ec.Entities[0][consts.lockn])
            {
                return false; //no user or already unlocked
            }
            else
            {
                ec.Entities[0][consts.lockn] = false;
                service.Update(ec.Entities[0]);
                return true;
            }
        }
    }

    public override void UpdateUser(MembershipUser user)
    {//TC
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression c = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            c.AttributeName = consts.accountid;
            c.Operator = ConditionOperator.Equal;
            c.Values.Add(user.ProviderUserKey);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression f = new FilterExpression();
            f.Conditions.Add(c);
            f.Conditions.Add(deleteCondition);
            f.Conditions.Add(appCondition);

            QueryExpression q = new QueryExpression(consts.useraccount);
            q.ColumnSet.AllColumns = true;
            q.Criteria.AddFilter(f);

            EntityCollection ec = service.RetrieveMultiple(q);

            if (ec.Entities.Count == 0)
            {
                return;
            }

            ec.Entities[0][consts.username] = user.UserName;
            ec.Entities[0][consts.securityquestion] = user.PasswordQuestion;
            ec.Entities[0][consts.email] = user.Email;
            ec.Entities[0][consts.timelocked] = user.LastLockoutDate;
            ec.Entities[0][consts.lastlogin] = user.LastLoginDate;
            ec.Entities[0][consts.accountcreation] = user.CreationDate;
            ec.Entities[0][consts.lockn] = user.IsLockedOut;//TODO: account for acivities last password change and last activity

            service.Update(ec.Entities[0]);

            return;
        }
    }

    public override bool ValidateUser(string username, string password)
    {//bcd
        using (OrganizationService service = new OrganizationService(OurConnect()))
        {

            ConditionExpression condition = new ConditionExpression();
            ConditionExpression deleteCondition = new ConditionExpression();
            ConditionExpression appCondition = new ConditionExpression();

            condition.AttributeName = consts.username;
            condition.Operator = ConditionOperator.Equal;
            condition.Values.Add(username);

            deleteCondition.AttributeName = consts.deleteduser;
            deleteCondition.Operator = ConditionOperator.Equal;
            deleteCondition.Values.Add(false);

            appCondition.AttributeName = consts.applicationname;
            appCondition.Operator = ConditionOperator.Equal;
            appCondition.Values.Add(_ApplicationName);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(condition);
            filter.Conditions.Add(deleteCondition);
            filter.Conditions.Add(appCondition);

            QueryExpression query = new QueryExpression(consts.useraccount);
            query.ColumnSet.AllColumns = true;
            query.Criteria.AddFilter(filter);

            EntityCollection ec = service.RetrieveMultiple(query);

            if (ec.Entities.Count == 0)
                return false;//the username does not exist

            if ((bool)ec.Entities[0][consts.lockn])
                return false;//the account is locked

            if (!ec.Entities[0][consts.password].Equals(password)) //(EncryptPassword(StringToAsci(password))))//user exists, but pass is wrong
            {
                //need to log a failed login attempt
                if (ec.Entities[0][consts.firstfailed] == null)//checking for first failed login
                    ec.Entities[0][consts.firstfailed] = DateTime.Now;

                if ((DateTime.Now - (DateTime)ec.Entities[0][consts.firstfailed]).Minutes >= _PasswordAttemptWindow)//password window/login attempt reset
                {
                    ec.Entities[0][consts.loginattempts] = 0;
                    ec.Entities[0][consts.firstfailed] = DateTime.Now;
                }

                ec.Entities[0][consts.loginattempts] = (int)ec.Entities[0][consts.loginattempts] + 1;//increment login attempts

                if ((int)ec.Entities[0][consts.loginattempts] >= _MaxInvalidPasswordAttempts)//check if user has exceed max login attempts
                    ec.Entities[0][consts.lockn] = true;

                service.Update(ec.Entities[0]);//update user information
                return false;
            }
            else
            {
                //reset attributes of login stuff
                ec.Entities[0][consts.online] = true;
                ec.Entities[0][consts.firstfailed] = null;
                ec.Entities[0][consts.loginattempts] = 0;
                //set last login date
                ec.Entities[0][consts.lastlogin] = DateTime.Now;
                //TODO: mark last activity

                service.Update(ec.Entities[0]);
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