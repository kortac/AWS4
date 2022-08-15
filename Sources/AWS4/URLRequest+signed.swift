//
//  File.swift
//  
//
//  Created by Matthias Reichmann on 15.08.22.
//

import Foundation

extension URLRequest {
    /// Signs a URLRequest for the service, region, access key id and secret access key. Optionally a
    /// date can be given that will be stored in X-Amz-Date header.
    ///
    /// - Returns: Signed url request. Do **not** change any request data after calling this function!
    func signed(service: AWS4.Service, region: String, accessKeyId: String,
                secretAccessKey: String, date: Date = Date()) -> URLRequest {
        let aws = AWS4(region: region, accessKeyId: accessKeyId, secretAccessKey: secretAccessKey)
        
        return aws.sign(request: self, for: service, date: date)
    }
    
    /// Signs a URLRequest for the service and region. Optionally a date can be given that will be stored in
    /// X-Amz-Date header. Access key id will be retrieved from Info.plist key AWS\_ACCESSKEYID. Secret
    /// access key will be retrieved from Info.plist key AWS\_SECRETACCESSKEY.
    ///
    /// - Returns: Signed url request. Do **not** change any request data after calling this function!
    func signed(service: AWS4.Service, region: String, date: Date = Date()) -> URLRequest {
        let aws = AWS4(region: region)

        return aws.sign(request: self, for: service, date: date)
    }
    
    /// Signs a URLRequest for the service. Optionally a date can be given that will be stored in
    /// X-Amz-Date header. Access key id will be retrieved from Info.plist key AWS\_ACCESSKEYID. Secret
    /// access key will be retrieved from Info.plist key AWS\_SECRETACCESSKEY. Region will be retrieved
    /// from Info.plist key AWS\_REGION.
    ///
    /// - Returns: Signed url request. Do **not** change any request data after calling this function!
    func signed(service: AWS4.Service, date: Date = Date()) -> URLRequest {
        let aws = AWS4()

        return aws.sign(request: self, for: service, date: date)
    }
}
