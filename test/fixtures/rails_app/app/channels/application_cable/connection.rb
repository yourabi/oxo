module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :oxo_session

    def connect
      self.oxo_session = cookies[:oxo_cable_session]
      reject_unauthorized_connection unless oxo_session == "ok"
    end
  end
end
