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

using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Client;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Discovery;
using Microsoft.Xrm.Client.Services;
using Microsoft.Xrm.Sdk.Metadata;

public class CRMMembershipProvider : MembershipProvider
{
    /*BEGINNING OF INITIALIZE FUNCTION*/
    private string _ApplicationName;
    private bool _EnablePasswordReset;
    private bool _EnablePasswordRetrieval = false;
    private bool _RequiresQuestionAndAnswer = false;
    private bool _RequireUniqueEmail = true;
    private int _MaxInvalidPasswordAttempts;
    private int _PasswordAttemptWindow;
    private int _MinRequiredPasswordLength;
    private int _MinRequiredNonalphanumericCharacters;
    private string _PasswordStrengthRegularExpression;
    private MembershipPasswordFormat _PasswordFormat = MembershipPasswordFormat.Hashed;
    private string _ConnectionStringName;

    private string GetConfigValue(string configValue, string defaultValue)
    {
        if (string.IsNullOrEmpty(configValue))
            return defaultValue;
        return configValue;
    }

    public override void Initialize(string name, NameValueCollection config)
    {//MAS
        if (config == null)
            throw new ArgumentNullException("config");

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
            GetConfigValue(config["connectionStringName"], "")); //todo: default to exception
    }

    /*CONNECTION AND QUERY*/
    public OrganizationService OurConnect()
    {
        var connection = new CrmConnection(_ConnectionStringName);
        var service = new OrganizationService(connection);
        return service;
    }

    /*CONVERT STRING TP ASCI FOR ENCRYPT/DECRYPT*/
    private byte[] StringToAsci(string password)
    {
        System.Text.ASCIIEncoding newEncoding = new System.Text.ASCIIEncoding();
        byte[] newBytes = newEncoding.GetBytes(password);
        return newBytes;
    }

    /*STREAMLINE GETUSER PROCESS*/
    public MembershipUser GetUser(string username)
    {//MAS
        var service = OurConnect(); //intialize connection

        ConditionExpression condition = new ConditionExpression(); //create new condition
        condition.AttributeName = "rosetta_username"; //column we want to check against
        condition.Operator = ConditionOperator.Equal; //checking against equal values
        condition.Values.Add(username); //check username against rosetta_username in CRM

        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter

        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.ColumnSet.AllColumns = true; 
        query.Criteria.AddFilter(filter); //query CRM with the new filter for username
        EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same username

        if (ec.Entities.Count != 0){
            return null;
        }
        else{
           string _usernameN = (string)ec[0]["rosetta_username"];
           string _securityQuestionN = (string)ec[0]["rosetta_securityquestion"];
           string _emailN = (string)ec[0]["rosetta_email"];
           DateTime _timeLockedN = (DateTime)ec[0]["rosetta_timelocked"];
           DateTime _lastLoginTimeN = (DateTime)ec[0]["rosetta_lastlogin"];
           DateTime _accountCreationN = (DateTime)ec[0]["rosetta_accountcreation"];
           DateTime _lastPasswordChangedDate = DateTime.Now;
           DateTime _lastAcivityDate = DateTime.Now;
           bool _lockN = (bool)ec[0]["rosetta_lock"];
           Guid _accountId = (Guid)ec[0]["rosetta_useraccountid"];
            

           MembershipUser user = new MembershipUser("CRMMembershipProvider",
                                                     _usernameN,
                                                     _accountId,
                                                     _emailN,
                                                     _securityQuestionN,
                                                     "",
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
        var service = OurConnect();
  
        ConditionExpression c = new ConditionExpression();
        c.AttributeName = "rosetta_username";
        c.Operator = ConditionOperator.Equal;
        c.Values.Add(username);

        FilterExpression f = new FilterExpression();
        f.Conditions.Add(c);

        QueryExpression q = new QueryExpression("rosetta_useraccount");
        q.ColumnSet.AddColumn("rosetta_password");
        q.ColumnSet.AddColumn("rosetta_username");
        q.Criteria.AddFilter(f);

        EntityCollection ec = service.RetrieveMultiple(q); 
      
        if (ec.Entities.Count == 0)
        {
            //if username doesn't exist
            return false;
        }
        else
        {
            if (EncryptPassword(StringToAsci(oldPassword)) != ec.Entities[0]["rosetta_password"])
            {
                return false;
            }
            //if the same overwrite with new password
            else
            {
                ec.Entities[0]["rosetta_password"] = EncryptPassword(StringToAsci(oldPassword));

                service.Update(ec.Entities[0]);
                return true;
            }
        }
    }

    public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
    {//bcd
        var service = OurConnect();

        ConditionExpression condition = new ConditionExpression();
        condition.AttributeName = "rosetta_username";
        condition.Operator = ConditionOperator.Equal;
        condition.Values.Add(username);

        ConditionExpression condition2 = new ConditionExpression();
        condition2.AttributeName = "rosetta_password";
        condition2.Operator = ConditionOperator.Equal;
        condition2.Values.Add(EncryptPassword(StringToAsci(password)));

        FilterExpression filter = new FilterExpression();
        filter.Conditions.Add(condition);
        filter.Conditions.Add(condition2);

        QueryExpression query = new QueryExpression("rosetta_useraccount");
        query.ColumnSet.AddColumns("rosetta_securityquestion");
        query.ColumnSet.AddColumns("rosetta_securitypassword");
        query.Criteria.AddFilter(filter);

        EntityCollection ec = service.RetrieveMultiple(query);

        if (ec.Entities.Count == 0)
        {
            //user doesn't exist
            return false;
        }
        else
        {
            ec.Entities[0]["rosetta_securityquestion"] = newPasswordQuestion;
            ec.Entities[0]["rosetta_securityanswer"] = newPasswordAnswer;

            service.Update(ec.Entities[0]);//success
            return true;
        }
    }
    
    public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
    {//MAS
        var service = OurConnect(); //intialize connection

        ConditionExpression condition = new ConditionExpression(); //create new condition
        condition.AttributeName = "rosetta_username"; //column we want to check against
        condition.Operator = ConditionOperator.Equal; //checking against equal values
        condition.Values.Add(username); //check username against rosetta_username in CRM

        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter

        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.Criteria.AddFilter(filter); //query CRM with the new filter for username
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
                Entity newMember = new Entity("rosetta_useraccount");

                newMember["rosetta_useraccountid"] = providerUserKey;
                newMember["rosetta_name"] = username;
                newMember["rosetta_username"] = username;
                newMember["rosetta_password"] = password;//Encoding.ASCII.GetString(EncryptPassword(StringToAsci(password)));
                newMember["rosetta_email"] = email;
                newMember["rosetta_securityquestion"] = passwordQuestion;
                newMember["rosetta_securityanswer"] = passwordAnswer;
                newMember["rosetta_applicationname"] = _ApplicationName;
                newMember["rosetta_deleteduser"] = false;
                newMember["rosetta_lock"] = false;
                newMember["rosetta_online"] = false;
                newMember["rosetta_loginattempts"] = 0;
                newMember["rosetta_accountcreation"] = DateTime.Now;
                newMember["rosetta_firstfailed"] = DateTime.Now;
                newMember["rosetta_lastlogin"] = DateTime.Now;
                newMember["rosetta_timelocked"] = DateTime.Now;

                Guid _accountID = service.Create(newMember);
                status = MembershipCreateStatus.Success;

                return GetUser(username);
           }
        }
    }
    
    protected override byte[] DecryptPassword(byte[] encodedPassword)
    {
        return base.DecryptPassword(encodedPassword);
    }

    public override bool DeleteUser(string username, bool deleteAllRelatedData)
    {//tc
        var service = OurConnect();
 
        ConditionExpression c = new ConditionExpression();
        c.AttributeName = "rosetta_username";
        c.Operator = ConditionOperator.Equal;
        c.Values.Add(username);

        FilterExpression f = new FilterExpression();
        f.Conditions.Add(c);

        QueryExpression q = new QueryExpression("rosetta_useraccount");
        q.ColumnSet.AddColumn("rosetta_username");
        q.ColumnSet.AddColumn("rosetta_deleteduser");
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
                if ((bool)ec.Entities[0]["rosetta_deleteduser"])
                {
                    return false;
                }
                else
                {//soft delete
                    ec.Entities[0]["rosetta_deleteduser"] = true;
                    service.Update(ec.Entities[0]);
                    return true;
                }
            }
            else 
            {//hard delete
                service.Delete("rosetta_useraccount", ec.Entities[0].Id);
                return true;
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
    {
        return base.EncryptPassword(password);
    }

    protected override byte[] EncryptPassword(byte[] password, MembershipPasswordCompatibilityMode legacyPasswordCompatibilityMode)
    {
        return base.EncryptPassword(password, legacyPasswordCompatibilityMode);
    }
    
    public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
    {//JH

        var service = OurConnect(); //intialize connection

        ConditionExpression condition = new ConditionExpression(); //creates a new condition.
        condition.AttributeName = "rosetta_email"; //column we want to check against
        condition.Operator = ConditionOperator.Equal; //checking against equal values
        condition.Values.Add(emailToMatch); //checks email against rosetta_email in CRM
       
        ConditionExpression condition2 = new ConditionExpression();// filters out soft deleted users.
        condition2.AttributeName = "rosetta_deletedusers";
        condition2.Operator = ConditionOperator.Equal;
        condition2.Values.Add(false);
      
        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter
        filter.Conditions.Add(condition2); //add conditon 2 to the filter
        
        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.ColumnSet.AllColumns = true;
        query.Criteria.AddFilter(filter); //query CRM with the new filter for email
        EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same email

        totalRecords = ec.TotalRecordCount;
      
        if (totalRecords != 0 && totalRecords >= ((pageSize*pageIndex)+1))
        {
            MembershipUserCollection usersToReturn = new MembershipUserCollection();
            var start = pageSize * pageSize;
            var end = (pageSize * pageSize) + (pageSize-(totalRecords%pageSize));
            for(int i=start;i<end;i++)
            {
                MembershipUser TempUser = GetUser((string)ec.Entities[i]["rosetta_username"]);
                usersToReturn.Add(TempUser); 
            }
            return usersToReturn;
         }
        else
        {
            return null;
        }
    }

    public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
    {//MAS
        var service = OurConnect(); //intialize connection

        ConditionExpression condition = new ConditionExpression(); //creates a new condition.
        condition.AttributeName = "rosetta_username"; //column we want to check against
        condition.Operator = ConditionOperator.Equal; //checking against equal values
        condition.Values.Add(usernameToMatch); //checks email against rosetta_email in CRM

        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter

        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
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
                MembershipUser TempUser = GetUser((string)ec.Entities[i]["rosetta_username"]);
                usersToReturn.Add(TempUser);

            }
            return usersToReturn;
        }
        else
        {
            return null;
        }
    }

    public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
    {//MAS
        var service = OurConnect();

        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same email

        totalRecords = ec.TotalRecordCount;

        if (totalRecords != 0 && totalRecords >= ((pageSize * pageIndex) + 1))
        {
            MembershipUserCollection usersToReturn = new MembershipUserCollection();
            var start = pageSize * pageIndex;
            var end = (pageSize * pageIndex) + pageSize;
            for (int i = start; i < end; i++)
            {
                MembershipUser TempUser = GetUser((string)ec.Entities[i]["rosetta_username"]);
                usersToReturn.Add(TempUser);

            }
            return usersToReturn;
        }
        else
        {
            return null;
        }
    }

    public override int GetNumberOfUsersOnline()
    {//JH
        var service = OurConnect(); //intialize connectio

        ConditionExpression condition = new ConditionExpression(); //creates a new condition.
        condition.AttributeName = "rosetta_online"; //column we want to check against.
        condition.Operator = ConditionOperator.Equal;//sets the comparing. 
        condition.Values.Add(true);//check to see if users are online.
        
        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter
        
        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.ColumnSet.AddColumn("rosetta_username");
        query.Criteria.AddFilter(filter); //query CRM with the new filter for users online 
        EntityCollection ec = service.RetrieveMultiple(query);  

        return ec.TotalRecordCount;
    }

    public override string GetPassword(string username, string answer)
    {//CC
        var service = OurConnect(); //initialize connection

        ConditionExpression condition = new ConditionExpression(); //creates a new condition
        condition.AttributeName = "rosetta_username"; //column to check against (trying to find username)
        condition.Operator = ConditionOperator.Equal; //checking agasint equal values
        condition.Values.Add(username); //check passed username value to password field in CRM

        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to filter

        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
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
                if (_PasswordFormat == MembershipPasswordFormat.Hashed) //checks if passwords are hashed. Cannot retrieve hashed passwords
                {
                    return null;
                }
                else
                {
                    if (_RequiresQuestionAndAnswer == true) //checks if the answer to the security question is needed
                    {
                        if ((string)ec.Entities[0]["rosetta_securityanswer"] == answer) //for now, check the value of the first entity in the collection agasint the answer passed
                        {
                            return (string)ec.Entities[0]["rosetta_password"]; //return the password from the first entity in the collection from the query
                        }
                        else
                        {
                            return null;
                        }
                    }
                    else
                    {
                        return (string)ec.Entities[0]["rosetta_password"]; //return the password from the first entity in the collection from the query
                    }
                }
            }
            else
            {
                return null;
            }
        }
    }

    public override MembershipUser GetUser(string username, bool userIsOnline)
    {//JH
        var service = OurConnect(); //intialize connection to CRM

        ConditionExpression condition = new ConditionExpression();
        condition.AttributeName = "rosetta_username";
        condition.Operator = ConditionOperator.Equal;
        condition.Values.Add(username);

        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter

        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.Criteria.AddFilter(filter); //query CRM with the new filter for email
        query.ColumnSet.AllColumns = true;
        EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same email

        if (ec.Entities.Count == 0)
        {
            return null;
        }
        else
        {
            if (userIsOnline == (bool)ec.Entities[0]["rosetta_online"])
                return GetUser((string)ec.Entities[0]["rosetta_username"]);
            return null;
        }
        
    }

    public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
    {//MAS
        var service = OurConnect();

        ColumnSet attributes = new ColumnSet(new string[] { "rosetta_username", "rosetta_online" });
        Entity e = service.Retrieve("rosetta_useraccount", (Guid)providerUserKey, attributes);

        if ((string)e["rosetta_username"]=="")
        {
            return null;
        }
        else
        {
            if(userIsOnline == (bool)e["rosetta_online"])
                return GetUser((string)e["rosetta_username"]);
            return null;
        }

    }
    
    public override string GetUserNameByEmail(string email)
    {//bcd
        var service = OurConnect();

        ConditionExpression condition = new ConditionExpression();
        condition.AttributeName = "rosetta_email";
        condition.Operator = ConditionOperator.Equal;
        condition.Values.Add(email);

        FilterExpression filter = new FilterExpression();
        filter.Conditions.Add(condition);
       
        QueryExpression query = new QueryExpression("rosetta_useraccount");
        query.ColumnSet.AddColumn("rosetta_username");
        query.Criteria.AddFilter(filter);
        EntityCollection collection = service.RetrieveMultiple(query);

        if (collection.Entities.Count == 0)
            return null;
        else//return username
        {
            Guid Retrieve_ID = collection[0].Id;
            ColumnSet attributies = new ColumnSet(new string[] { "rosetta_username" });
            Entity retrievedEntity = service.Retrieve("rosetta_useraccount", Retrieve_ID, attributies);

            return retrievedEntity["rosetta_username"].ToString();
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
        var service = OurConnect();
        
        if (!EnablePasswordReset)
        {
            return null;
        }
        else
        {//reset password based on assigned regular expresssion
            ConditionExpression condition = new ConditionExpression();
            condition.AttributeName = "rosetta_username";
            condition.Operator = ConditionOperator.Equal;
            condition.Values.Add(username);

            FilterExpression filter = new FilterExpression();
            filter.Conditions.Add(condition);

            QueryExpression query = new QueryExpression("rosetta_useraccount");
            query.ColumnSet.AddColumn("rosetta_securityanswer");
            query.Criteria.AddFilter(filter);
            EntityCollection ec = service.RetrieveMultiple(query);

            if (ec.Entities.Count == 0)
                return null;
            else
            {
                string NewPass = Membership.GeneratePassword(_MinRequiredPasswordLength, 2);
                ec.Entities[0]["rosetta_password"] = NewPass;
                service.Update(ec.Entities[0]);
                return NewPass;
            }          
        }
    }

    public override bool UnlockUser(string userName)
    {
        var service = OurConnect();

        ConditionExpression condition = new ConditionExpression();
        condition.AttributeName = "rosetta_username";
        condition.Operator = ConditionOperator.Equal;
        condition.Values.Add(userName);

        FilterExpression filter = new FilterExpression();
        filter.Conditions.Add(condition);

        QueryExpression query = new QueryExpression("rosetta_useraccount");
        query.ColumnSet.AddColumns("rosetta_lock");
        query.Criteria.AddFilter(filter);

        EntityCollection ec = service.RetrieveMultiple(query);

        if (ec.Entities.Count == 0 || !(bool)ec.Entities[0]["rosetta_lock"])
        {
            return false; //no user or already unlocked
        }
        else
        {
            ec.Entities[0]["rosetta_lock"]= false;
            service.Update(ec.Entities[0]);
            return true;
        }
    }

    public override void UpdateUser(MembershipUser user)
    {
        var service = OurConnect();

        ConditionExpression c = new ConditionExpression();
        c.AttributeName = "rosetta_useraccountid";
        c.Operator = ConditionOperator.Equal;
        c.Values.Add(user.ProviderUserKey);
        
        FilterExpression f = new FilterExpression();
        f.Conditions.Add(c);
 		
        QueryExpression q = new QueryExpression("rosetta_useraccount");
        q.ColumnSet.AllColumns = true;
        q.Criteria.AddFilter(f);
       
        EntityCollection ec = service.RetrieveMultiple(q);

        if (ec.Entities.Count == 0)
        {
            return;
        }
        
        ec.Entities[0]["rosetta_username"] = user.UserName;
        ec.Entities[0]["rosetta_securityquestion"] = user.PasswordQuestion;
        ec.Entities[0]["rosetta_email"] = user.Email;
        ec.Entities[0]["rosetta_timelocked"] = user.LastLockoutDate;
        ec.Entities[0]["rosetta_lastlogin"] = user.LastLoginDate;
        ec.Entities[0]["rosetta_accountcreation"] = user.CreationDate;
        ec.Entities[0]["rosetta_lock"] = user.IsLockedOut;

        service.Update(ec.Entities[0]);

        return;
    }

    public override bool ValidateUser(string username, string password)
    {
        var service = OurConnect();

        ConditionExpression condition = new ConditionExpression();
        condition.AttributeName = "rosetta_username";
        condition.Operator = ConditionOperator.Equal;
        condition.Values.Add(username);

        FilterExpression filter = new FilterExpression();
        filter.Conditions.Add(condition);

        QueryExpression query = new QueryExpression("rosetta_useraccount");
        query.ColumnSet.AllColumns = true;
        query.Criteria.AddFilter(filter);

        EntityCollection ec = service.RetrieveMultiple(query);

        if (ec.Entities.Count == 0)
            return false;//the username does not exist

        if ((bool)ec.Entities[0]["rosetta_lock"])
            return false;//the account is locked

        if (!ec.Entities[0]["rosetta_password"].Equals(password)) //(EncryptPassword(StringToAsci(password))))//user exists, but pass is wrong
        {
            //need to log a failed login attempt
            if (ec.Entities[0]["rosetta_firstfailed"] == null)//checking for first failed login
                ec.Entities[0]["rosetta_firstfailed"] = DateTime.Now;

            if ((DateTime.Now - (DateTime)ec.Entities[0]["rosetta_firstfailed"]).Minutes >= _PasswordAttemptWindow)//password window/login attempt reset
            {
                ec.Entities[0]["rosetta_loginattempts"] = 0;
                ec.Entities[0]["rosetta_firstfailed"] = DateTime.Now;
            }

            ec.Entities[0]["rosetta_loginattempts"] = (int)ec.Entities[0]["rosetta_loginattempts"] + 1;//increment login attempts

            if ((int)ec.Entities[0]["rosetta_loginattempts"] == _MaxInvalidPasswordAttempts)//check if user has exceed max login attempts
                ec.Entities[0]["rosetta_lock"] = 1;

            service.Update(ec.Entities[0]);//update user information
            return false;
        }
        else
        {
            //reset attributes of login stuff
            ec.Entities[0]["rosetta_online"] = 1;
            ec.Entities[0]["rosetta_firstfailed"] = null;
            ec.Entities[0]["rosetta_loginattempts"] = 0;

            service.Update(ec.Entities[0]);
            return true;
        }
    }    
}