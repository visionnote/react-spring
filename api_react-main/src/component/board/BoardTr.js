import { Link } from "react-router-dom";

function BoardTr(props) {
  let url = "/board/view?no=" + props.row.no;
  let nested = "";

  for (let i = 0; i < props.row.nested; i++) {
    nested += "&nbsp;&nbsp;&nbsp;&nbsp;";
  }
  if (props.row.nested > 0)
    nested += "<img src='/img/ico_re.png' alt=''/>&nbsp;&nbsp;";
  return (
    <>
      <tr>
        <td>{props.row.no}</td>
        <td className="txt_l">
          <Link to={url}>
            <span dangerouslySetInnerHTML={{ __html: nested }}></span>
            {props.row.title} [{props.row.comment.length}]
          </Link>
        </td>
        <td>{props.row.viewcnt}</td>
        <td className="writer">{props.row.user ? props.row.user.name : ""}</td>
        <td className="date">{props.row.writedate.substring(0, 10)}</td>
      </tr>
    </>
  );
}

export default BoardTr;
