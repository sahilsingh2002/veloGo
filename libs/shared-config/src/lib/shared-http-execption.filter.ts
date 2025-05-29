import { ExceptionFilter, Catch, ArgumentsHost, HttpException, Logger } from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
    // constructor(private logger: Logger) {}
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    const info =  exception.message
    // this.logger.error(
    //     `${request.method} ${request.originalUrl} ${status} error: ${err}`
    // )
    response
      .status(status)
      .json({
        success: false,
        // timestamp: new Date().toISOString(),
        // path: request.url,
        info
      });
  }
}