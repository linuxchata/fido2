using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Shark.Fido2.Sample.Filters;

public class RestApiExceptionFilter(ILogger<RestApiExceptionFilter> logger) : IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        var problem = new ProblemDetails
        {
            Title = "An unexpected error occurred.",
            Detail = context.Exception.Message,
            Status = (int)HttpStatusCode.InternalServerError,
        };

        context.Result = new ObjectResult(problem)
        {
            StatusCode = (int)HttpStatusCode.InternalServerError,
        };

        context.ExceptionHandled = true;

        logger.LogError(
            "Unhandled exception occurred while processing request: {ExceptionMessage}",
            context.Exception.Message);
    }
}