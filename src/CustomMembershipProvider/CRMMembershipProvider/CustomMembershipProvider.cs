/*bcd note to guys: in order to know if the password stuff is working we need the validate user stuff to work so that we can get to the point
 where we can go and check our user account settings. I realize we are still working on everything, but there will be no way to test the pass
 word stuff until that basica functionality is setup*/


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
    //the following private variables are for the dynamic names of the attribute names that are used in CRM. Currently, the attribute names
    //are hard coded in but will be replaced with these variables to make the code more dynamic.
    private Guid _accountId;
    /*private string _passwordN;
    private string _usernameN;
    private string _securityQuestionN;
    private string _securityAnswerN;
    private string _emailN;
    private bool _onlineN;
    private bool _lockN;
    private int _loginAttemptsN;
    private DateTime _timeLockedN;
    private DateTime _firstFailedN;
    private DateTime _lastLoginTimeN;
    private DateTime _accountCreationN;*/
    
    //our connection method
    public OrganizationService OurConnect() 
    {//tc
        var connection = new CrmConnection(_ConnectionStringName);
        var service = new OrganizationService(connection);
        return service;
    }

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
        //find user by username
        //create condition for query
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

<<<<<<< HEAD
        EntityCollection result = service.RetrieveMultiple(q);
=======
        EntityCollection result = service.RetrieveMultiple(q);//why do we need to retrieve multiple in this case? bcd
                                                                //we use retrieve multiple because retrieve() requires GUID
>>>>>>> 453fd585382949f20d61cac34febcafe795478ee
        //compare oldPassword to the current pasword
        if (result.Entities.Count != 0)
        {
            //if username doesn't exist
            return false;
        }
<<<<<<< HEAD
        else
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            byte[] bytes = encoding.GetBytes(oldPassword);
            if (EncryptPassword(bytes) != result.Entities[0]["rosetta_password"])// assuming that entities[0] is the only entity since i am only making onw with my query
            {
                return false;
                //throw new Exception("no user/pass match");
            }
            //if the same overwrite with new password
            else
            {
                //is this good here or do we need encrypted pass?
                System.Text.ASCIIEncoding newEncoding = new System.Text.ASCIIEncoding();
                byte[] newBytes = newEncoding.GetBytes(newPassword);
                newBytes = EncryptPassword(newBytes);
                result.Entities[0]["rosetta_password"] = newBytes;

                service.Update(result.Entities[0]);
                return true;
            }
=======
        //if the same overwrite with new password
        else {
            //is this good here or do we need encrypted pass? 
            //we have an encrypt password function we have to write anyway, so you may want to move some of this code around for that. Scroll down a littl and you will see it
            System.Text.ASCIIEncoding newEncoding = new System.Text.ASCIIEncoding();
            byte[] newBytes = newEncoding.GetBytes(newPassword);
            newBytes = EncryptPassword(newBytes);
            result.Entities[0]["rosetta_password"] = newBytes;

            service.Update(result.Entities[0]);
            return true;
>>>>>>> 0e747aaddfa878adacda16c568660f4882518c9c
        }
    }

    public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
    {//bcd
        var service = OurConnect(); //intialize connection to CRM

        //for updating we do not need to query for the existance of a user since, technically, the user exists. However we do not know the GUID of the user without querying?
        //check for username
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

        EntityCollection collection = service.RetrieveMultiple(query);

        if (collection.Entities.Count == 0)
        {
            //user doesn't exist
            return false;
            //throw new Exception("incorrect password!");
        }
        else//I wont know if this works for sure until we can validate user and have a modification screen
        {
            collection.Entities[0]["rosetta_securityquestion"] = newPasswordQuestion;
            collection.Entities[0]["rosetta_securityanswer"] = newPasswordAnswer;

            service.Update(collection.Entities[0]);//success
            return true;
            //throw new Exception("Successfully changed Security Question and Answer!");
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
        //query.ColumnSet.AddColumns("rosetta_username"); <--commented because do not need in this situation-->
        query.Criteria.AddFilter(filter); //query CRM with the new filter for username
        EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same username
        
        if (ec.Entities.Count != 0)
        {
            status = MembershipCreateStatus.DuplicateUserName;
            return null;
        }
        /*else
        {
            if (_RequireUniqueEmail && GetUserNameByEmail(email) != null)
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }*/
            else
            {
                Entity newMember = new Entity("rosetta_useraccount");

                newMember["rosetta_name"] = username;
                newMember["rosetta_username"] = username;
                newMember["rosetta_password"] = EncryptPassword(StringToAsci(password));
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
           // }
        }
        /*foreach (Entity act in ec.Entities)
        {
            Console.WriteLine("account name:" + act["name"]);
            Console.WriteLine("primary contact first name:" + act["primarycontact.firstname"]);
            Console.WriteLine("primary contact last name:" + act["primarycontact.lastname"]);
        }*/

        
    }
    
    protected override byte[] DecryptPassword(byte[] encodedPassword)
    {
        return base.DecryptPassword(encodedPassword);
    }

    public override bool DeleteUser(string username, bool deleteAllRelatedData)
    {//tc
        //soft delete, check if 'deleted' if not, 'delete'
        var service = OurConnect();
        //find user by username
        //create condition for query
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

        EntityCollection result = service.RetrieveMultiple(q);

<<<<<<< HEAD
        if (result.Entities[0]["rosetta_deleteduser"] == "Yes")
        {
            return false;
        }
        else {
            result.Entities[0]["rosetta_deleteduser"] = "Yes";
            service.Update(result.Entities[0]);
            return true;
=======
        if (result.Entities.Count() == 0)
        {
            return false;
        }
        else
        {
            if (deleteAllRelatedData == false)
            {
                if (result.Entities[0]["rosetta_deleteduser"] == "Yes")
                {
                    return false;
                }
                else
                {
                    result.Entities[0]["rosetta_deleteduser"] = "Yes";
                    service.Update(result.Entities[0]);
                    return true;
                }
            }
            else { 
                //DELETE ALL THE THINGS!
                service.Delete("rosetta_useraccount", result.Entities[0].Id);
                return true;
            }
>>>>>>> bd4e72a0e030565d13dc0511bfd5be49a0a1ad29
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
    private byte[] StringToAsci(string password)
    {
        System.Text.ASCIIEncoding newEncoding = new System.Text.ASCIIEncoding();
        byte[] newBytes = newEncoding.GetBytes(password);
        return newBytes;
    }
    public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
    {//JH

        var service = OurConnect(); //intialize connection

        ConditionExpression condition = new ConditionExpression(); //creates a new condition.
        condition.AttributeName = "rosetta_email"; //column we want to check against
        condition.Operator = ConditionOperator.Equal; //checking against equal values
        condition.Values.Add(emailToMatch); //checks email against rosetta_email in CRM
        
        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter
        
        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.ColumnSet.AllColumns = true;
        query.Criteria.AddFilter(filter); //query CRM with the new filter for email
        EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same email

        totalRecords = ec.TotalRecordCount;
       
        if (ec.TotalRecordCount != 0)
        {
            MembershipUserCollection usersToReturn = new MembershipUserCollection();
            foreach (Entity act in ec.Entities)//gets all the records out of ec assigns them to userstoreturn.
            {
                MembershipUser TempUser = GetUser((string)act["rosetta_username"]);
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
    {

        throw new NotImplementedException();
    }

    public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
    {
        throw new NotImplementedException();
    }

    public override int GetNumberOfUsersOnline()
    {//JH
<<<<<<< HEAD
        var service = OurConnect();
=======
        var service = OurConnect(); //intialize connection
>>>>>>> 453fd585382949f20d61cac34febcafe795478ee

        ConditionExpression condition = new ConditionExpression(); //creates a new condition.
        condition.AttributeName = "rosetta_online"; //column we want to check against.
        condition.Operator = ConditionOperator.Equal;//sets the comparing. 
        condition.Values.Add("Yes");//check to see if users are online.
        
        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter
        
        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.ColumnSet.AddColumn("rosetta_username");
        query.Criteria.AddFilter(filter); //query CRM with the new filter for users online 
        EntityCollection ec = service.RetrieveMultiple(query);  
		
		
        int usersOnline;
        usersOnline = ec.TotalRecordCount;
        return usersOnline;
        
		
		
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
            throw new Exception("Cannot retrieve password because user does not exist."); //no entities exist
        }
        else
        {
            if (EnablePasswordRetrieval) //if allowed to get password
            {
                if (_PasswordFormat == MembershipPasswordFormat.Hashed) //checks if passwords are hashed. Cannot retrieve hashed passwords
                {
                    throw new NotSupportedException("Cannot retrieve hashed passwords.");
                }
                else
                {
                    if (_RequiresQuestionAndAnswer == true) //checks if the answer to the security question is needed
                    {
                        if (ec.Entities[0].GetAttributeValue("rosetta_securityanswer") == answer) //for now, check the value of the first entity in the collection agasint the answer passed
                        {
                            return (string)ec.Entities[0].GetAttributeValue("rosetta_password"); //return the password from the first entity in the collection from the query
                        }
                        else
                        {
                            throw new Exception("Incorrect Answer to the security question."); //throw an exception that the answer doesn't match
                        }
                    }
                    else
                    {
                        return (string)ec.Entities[0].GetAttributeValue("rosetta_password"); //return the password from the first entity in the collection from the query
                    }
                }
            }
            else
            {
                throw new NotSupportedException("The current settings do not allow the password to be retrieved."); //throw exception that it is not supported to get password
            }
        }
    }

    public override MembershipUser GetUser(string username, bool userIsOnline)

    {
        return GetUser(username);
    }

    public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
    {//JH
        throw new NotImplementedException();
    }
    //function to streamline getuser process
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
        if (EnablePasswordReset == false)
        {
            throw new Exception("Resetting of passwords is not permitted");
        }
        else
        {//reset password based on assigned regular expresssion
            throw new NotImplementedException();
        }
    }

    public override bool UnlockUser(string userName)
    {
        throw new NotImplementedException();
    }

    public override void UpdateUser(MembershipUser user)
    {
        throw new NotImplementedException();
    }

    public override bool ValidateUser(string username, string password)
    {
        throw new NotImplementedException();
    }
    /*Start of Initialize method*/
    private string GetConfigValue(string configValue, string defaultValue)
    {
        if (string.IsNullOrEmpty(configValue))
            return defaultValue;
        return configValue;
    }
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
   // private string _ConnectionString;


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

        //An idea on how to use the connection string to dynamically connect our Library to the connection
        //_ConnectionString = ConfigurationManager.ConnectionStrings[_ConnectionStringName].ConnectionString;


    }
}