import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response, Request } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('error');
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const statusCode: number =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;
    const message: string =
      exception instanceof HttpException
        ? exception.message
        : `Internal Server Error`;

    this.logger.error(
      `error mewssage => ${message} , trace => ${exception.stack}`,
    );

    response.status(statusCode).json({
      statusCode,
      message,
      timeStamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
