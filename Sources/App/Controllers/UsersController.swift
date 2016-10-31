//
//  UsersController.swift
//  AuthTemplate
//
//  Created by Anthony Castelli on 10/29/16.
//
//

import Foundation
import Vapor
import HTTP
import Turnstile
import TurnstileCrypto
import TurnstileWeb

final class UsersController {
    
    // MARK: Authentication
    
    func register(request: Request) throws -> ResponseRepresentable {
        // Get our credentials
        guard let username = request.data["username"]?.string, let password = request.data["password"]?.string else {
            throw Abort.custom(status: Status.badRequest, message: "Missing username or password")
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
            throw Abort.custom(status: Status.badRequest, message: e.description)
        }
    }
    
    func login(request: Request) throws -> ResponseRepresentable {
        guard let username = request.data["username"]?.string, let password = request.data["password"]?.string else {
            throw Abort.custom(status: Status.badRequest, message: "Missing username or password")
        }
        let credentials = UsernamePassword(username: username, password: password)
        do {
            try request.auth.login(credentials)
            return try JSON(node: ["success": true, "user": request.user().makeNode()])
        } catch _ {
            throw Abort.custom(status: Status.badRequest, message: "Invalid username or password")
        }
    }
    
    func logout(request: Request) throws -> ResponseRepresentable {
        request.subject.logout()
        return try JSON(node: ["success": true])
    }
    
    // MARK: Custom Endpoints
    
    func me(request: Request) throws -> ResponseRepresentable {
        return try JSON(node: request.user().makeNode())
    }
    
}

extension Request {
    // Exposes the Turnstile subject, as Vapor has a facade on it.
    var subject: Subject {
        return storage["subject"] as! Subject
    }
}

