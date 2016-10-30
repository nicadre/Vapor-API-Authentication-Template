//
//  BasicAuthMiddleware.swift
//  AuthTemplate
//
//  Created by Anthony Castelli on 10/29/16.
//
//
// Originally from https://github.com/stormpath/Turnstile-Vapor-Example/blob/master/Sources/App/BasicAuthenticationMiddleware.swift

import Vapor
import HTTP
import Turnstile
import Auth


/**
 Takes a Basic Authentication header and turns it into a set of API Keys,
 and attempts to authenticate against it.
 */
class BasicAuthMiddleware: Middleware {
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        if let apiKey = request.auth.header?.basic {
            try? request.auth.login(apiKey, persist: false)
        }
        
        return try next.respond(to: request)
    }
}
