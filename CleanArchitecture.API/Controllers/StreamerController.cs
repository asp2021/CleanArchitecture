using CleanArchitecture.Application.Features.Streamers.Commands;
using CleanArchitecture.Application.Features.Streamers.Commands.DeleteStreamer;
using CleanArchitecture.Application.Features.Streamers.Commands.UpdateStreamer;
using CleanArchitecture.Application.Features.Streamers.Queries.GetStreamerListByUrl;
using CleanArchitecture.Application.Features.Streamers.Queries.GetStreamerListByUsername;
using CleanArchitecture.Application.Features.Streamers.Queries.Vms;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace CleanArchitecture.API.Controllers
{
    
    [ApiController]
    [Route("api/v1/[controller]")]
    public class StreamerController : ControllerBase
    {

        private IMediator _mediator;

        public StreamerController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpGet("ByUrl/{url}", Name ="GetStreamersByUrl")]
        [ProducesResponseType(typeof(IEnumerable<StreamersVm>),(int)HttpStatusCode.OK)]
        public async Task<ActionResult<IEnumerable<StreamersVm>>> GetStreamersByUrl(string url)
        {
            var query = new GetStreamerListByUrlQuery(url);
            var streamers = await _mediator.Send(query);
            return Ok(streamers);
        }

        [HttpGet("ByUsername/{username}", Name = "GetStreamersByUsername")]
        [ProducesResponseType(typeof(IEnumerable<StreamersVm>), (int)HttpStatusCode.OK)]
        public async Task<ActionResult<IEnumerable<StreamersVm>>> GetStreamersByUsername(string username)
        {
            var query = new GetStreamerListQuery(username);
            var streamers = await _mediator.Send(query);
            return Ok(streamers);
        }



        [HttpPost(Name = "CreateStreamer")]
        [Authorize(Roles = "Administrator")]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        public async Task<ActionResult<int>> CreateStreamer([FromBody] CreateStreamerCommand command)
        {
          return  await  _mediator.Send(command);
        }

        [HttpPut(Name = "UpdateStreamer")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesDefaultResponseType]
        public async Task<ActionResult> UpdateStreamer([FromBody] UpdateStreamerCommand command)
        {
            await _mediator.Send(command);

            return NoContent();
        }


        [HttpDelete("{id}", Name = "DeleteStreamer")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesDefaultResponseType]
        public async Task<ActionResult> DeleteStreamer(int id)
        {
            var command = new DeleteStreamerCommand
            {
                Id = id
            };

            await _mediator.Send(command);

            return NoContent();    
        }

    }
}
