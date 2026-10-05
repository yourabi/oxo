class EchoChannel < ApplicationCable::Channel
  def subscribed
    stream_from stream_name
  end

  def speak(data)
    payload = {
      message: data["message"],
      room: params[:room],
      transport: "standalone-action-cable"
    }
    ActionCable.server.broadcast(stream_name, payload.merge(fanout: Oxo::PressureFixture.cable_adapter_label))
  end

  def receive(data)
    speak(data)
  end

  private

  def stream_name
    "oxo:fixture:#{params[:room]}"
  end
end
