import Vapor
import Auth
import HTTP
import Cookies
import Turnstile
import TurnstileCrypto
import TurnstileWeb
import Fluent
import Foundation
//let drop = Droplet(database: database, availableMiddleware: ["auth": auth, "trustProxy": TrustProxyMiddleware()], preparations: [User.self])

let drop = Droplet()
drop.database = Database(MemoryDriver())
drop.preparations.append(User.self)
drop.middleware.append(AuthMiddleware<User>())
drop.middleware.append(TrustProxyMiddleware())

drop.get { req in
    return try drop.view.make("welcome", [
    	"message": drop.localization[req.lang, "welcome", "title"]
    ])
}


drop.group("api") { api in
    api.group("v1") { v1 in
        
        // Registration
        v1.post("register") { request in
            // Get our credentials
            guard let username = request.data["username"]?.string, let password = request.data["password"]?.string else {
                    return try JSON(node: ["error": "Missing username or password"])
            }
            let credentials = UsernamePassword(username: username, password: password)
            
            // Get any other parameters we need
            var parameters = [String : String]()
            guard let email = request.data["email"]?.string else {
                return try JSON(node: ["error": "Missing Email"])
            }
            parameters["email"] = email
            
            guard let name = request.data["name"]?.string else {
                return try JSON(node: ["error": "Missing Full Name"])
            }
            parameters["name"] = name
            
            // Try to register the user
            do {
                try _ = User.register(credentials: credentials, parameters: parameters)
                try request.auth.login(credentials)
                return try JSON(node: ["success": true, "user": request.user().makeNode()])
            } catch let e as TurnstileError {
                return try JSON(node: ["error": e.description])
            }
        }
        
        // Log In
        v1.post("login") { request in
            guard let username = request.data["username"]?.string, let password = request.data["password"]?.string else {
                return try JSON(node: ["error": "Missing username or password"])
            }
            let credentials = UsernamePassword(username: username, password: password)
            do {
                try request.auth.login(credentials)
                return try JSON(node: ["success": true, "user": request.user().makeNode()])
            } catch let e {
                return try JSON(node: ["error": "Invalid username or password"])
            }
        }

        
        // Secured Endpoints
        let protect = ProtectMiddleware(error: Abort.custom(status: .unauthorized, message: "Unauthorized"))
        v1.group(BasicAuthMiddleware(), protect) { secured in
            
            secured.get("me") { request in
                return try JSON(node: request.user().makeNode())
            }
            
        }
    }
}

drop.run()
