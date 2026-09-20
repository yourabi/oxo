# frozen_string_literal: true

class PressureController < ApplicationController
  def status
    render json: Oxo::PressureFixture.pool_status
  end

  def db
    result = Oxo::PressureFixture.db_probe(hold_ms: hold_ms)
    render json: result.fetch(:body), status: result.fetch(:status)
  end

  def hold
    result = Oxo::PressureFixture.db_hold(hold_ms: hold_ms)
    render json: result.fetch(:body), status: result.fetch(:status)
  end

  def redis
    result = Oxo::PressureFixture.redis_probe(hold_ms: hold_ms)
    render json: result.fetch(:body), status: result.fetch(:status)
  end

  private

  def hold_ms
    params.fetch(:hold_ms, "0").to_i.clamp(0, 5_000)
  end
end
