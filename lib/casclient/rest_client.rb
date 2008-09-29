module CASClient
  class RestClient < Client
    attr_writer :restful_url
    
    def configure(conf)
      @restful_url = conf[:restful_url]
      super
    end
   
    def restful_url
      @restful_url || (cas_base_url + "/v1/tickets")
    end
    
    def get_ticket_granting_ticket_resource(credentials)
      resp = submit_data_to_cas(restful_url, credentials.stringify_keys, '&')
      puts  "resp: #{resp.inspect}"
      case resp
      when Net::HTTPCreated then
        log.debug("successfully created a TGT")
        header = resp.to_hash
        return header['location']
      when Net::HTTPForbidden then
        log.warn("RestClient.get_ticket_granting_ticket_resource: credentials were incorrect")
        return nil
      when Net::HTTPBadRequest then
        log.error("RestClient.get_ticket_granting_ticket_resource: CAS server returned BadRequest")
        raise BadRequestException, res.body
      else
        log.warn "RestClient.get_ticket_granting_ticket_resource: an unexpected error occurred #{resp}"
        raise CASException, res.inspect
      end      
    end
    
    def get_service_ticket(credentials, service_url)      
      tgt_resource = get_ticket_granting_ticket_resource(credentials)
      data = credentials.merge(:service => CGI.escape(service_url)).stringify_keys
      resp = submit_data_to_cas(restful_url, data, '&')      
    end
    
  end

  class BadRequestException < CASException
  end
end