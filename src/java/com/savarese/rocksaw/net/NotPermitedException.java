package com.savarese.rocksaw.net;

import java.io.InterruptedIOException;

public class NotPermitedException extends InterruptedIOException {
  public NotPermitedException(String errorMessage) {
    super(errorMessage);
  }
}