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
        
        let usersController = UsersController()
        
        // Registration
        v1.post("register", handler: usersController.register)
        
        // Log In
        v1.post("login", handler: usersController.login)

        // Log Out
        v1.post("logout", handler: usersController.logout)
        
        // Secured Endpoints
        let protect = ProtectMiddleware(error: Abort.custom(status: .unauthorized, message: "Unauthorized"))
        v1.group(BasicAuthMiddleware(), protect) { secured in
            
            secured.get("me", handler: usersController.me)            
        }
    }
}

drop.run()
