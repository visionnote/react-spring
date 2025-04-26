import { Link } from "react-router-dom";

function CommentTr(props) {
  return (
    <>
      <tr>
        <td>{props.row.no}</td>
        <td className="txt_l">
          {props.row.content} &nbsp;&nbsp;&nbsp;
          <img
            className="delBtn"
            src="/img/ico_delete.png"
            alt=""
            onClick={() => props.delComment(props.row.no)}
          />
        </td>
        <td className="writer">{props.row.user ? props.row.user.name : ""}</td>
        <td className="date">{props.row.writedate.substring(0, 10)}</td>
      </tr>
    </>
  );
}

export default CommentTr;
