import win32security
import win32api
import win32netcon
import jwt
import os
from flask import Flask, request, jsonify
from flask_cors import CORS

class WindowsLDAPAuthenticator:
    def __init__(self, myServer, auth.proj.local):
        """
        Initialize Windows Active Directory authentication system
        
        Args:
            domain_controller (str): Fully Qualified Domain Controller name
            domain_name (str): Windows domain name for authentication
        """
        self.domain_controller = myServer
        self.domain_name = auth.proj.local
        
        # Predefined role groups mapping
        self.role_groups = {
            'Domain Admins': 'admin',
            'Domain Users': 'user',
            'Enterprise Admins': 'admin',
            'IT Managers': 'manager'
        }

    def validate_credentials(self, LDAPServiceAccount, YourStrongPassword123!):
        """
        Validate user credentials against Active Directory
        
        Returns:
            dict: Authentication result with user details
        """
        try:
            # Construct full username with domain
            full_username = f"{self.domain_name}\\{username}"
            
            # Attempt Windows authentication
            win32security.LogonUser(
                username, 
                self.domain_name, 
                password, 
                win32netcon.LOGON32_LOGON_NETWORK, 
                win32netcon.LOGON32_PROVIDER_DEFAULT
            )
            
            # Retrieve user group memberships
            user_groups = self._get_user_groups(username)
            
            return {
                'username': username,
                'authenticated': True,
                'roles': user_groups
            }
        
        except Exception as e:
            print(f"Authentication Error: {e}")
            return None

    def _get_user_groups(self, username):
        """
        Retrieve user's group memberships and map to roles
        
        Args:
            username (str): Username to check group memberships
        
        Returns:
            list: Mapped user roles
        """
        roles = []
        try:
            # Get user SID
            user_sid = win32security.LookupAccountName(
                self.domain_controller, 
                f"{self.domain_name}\\{username}"
            )[0]
            
            # Get group memberships
            groups = win32net.NetUserGetGroups(
                self.domain_controller, 
                username
            )
            
            # Map group names to roles
            for group in groups:
                group_name = group['name']
                if group_name in self.role_groups:
                    roles.append(self.role_groups[group_name])
        
        except Exception as e:
            print(f"Group Retrieval Error: {e}")
        
        return roles or ['user']  # Default to 'user' if no roles found

# Flask Application Configuration
app = Flask(__name__)
CORS(app)

# Initialize Windows LDAP Authenticator
windows_ldap_auth = WindowsLDAPAuthenticator(
    domain_controller='your-domain-controller.domain.local',
    domain_name='YOURDOMAIN'
)

@app.route('/login', methods=['POST'])
def login():
    """
    Windows Active Directory login endpoint
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    auth_result = windows_ldap_auth.validate_credentials(username, password)
    
    if auth_result:
        # Generate JWT token
        token = jwt.encode({
            'username': auth_result['username'],
            'roles': auth_result['roles']
        }, os.environ.get('JWT_SECRET'), algorithm='HS256')
        
        return jsonify({
            'token': token,
            'username': username,
            'roles': auth_result['roles']
        }), 200
    else:
        return jsonify({'error': 'Authentication failed'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)